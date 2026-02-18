package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/grandcat/zeroconf"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const configMapName = "mdns-gateway-registry"

type ServiceEntry struct {
	Instance  string   `json:"instance"`
	Service   string   `json:"service"`
	Domain    string   `json:"domain"`
	Port      int      `json:"port"`
	IPs       []string `json:"ips"`
	TXT       []string `json:"txt"`
	Origin    string   `json:"origin"`
	Source    string   `json:"source"` // "lan" or "cluster" — where this service was discovered
	Timestamp int64    `json:"timestamp"`
}

var (
	nodeName         = os.Getenv("NODE_NAME")
	nodeIP           = os.Getenv("NODE_IP")
	namespace        = os.Getenv("POD_NAMESPACE")
	lanIfaceName     = os.Getenv("LAN_IFACE")
	clusterIfaceName = os.Getenv("CLUSTER_IFACE")

	lanIface     net.Interface
	clusterIface net.Interface

	localAds   = map[string]*zeroconf.Server{}
	localMutex sync.Mutex

	// activeBrowsers tracks service types already being browsed per interface
	// to avoid spawning duplicate sub-browsers.
	activeBrowsers = map[string]struct{}{}
	browsersMutex  sync.Mutex

	// pendingServices buffers service writes; flushed in a single ConfigMap
	// update by runConfigMapWriter to avoid per-service API calls.
	pendingServices = map[string]string{}
	pendingMutex    sync.Mutex
	pendingDirty    bool

	// k8sServicesCache is a cached list of LoadBalancer services, refreshed
	// periodically to avoid listing on every mDNS event.
	k8sServicesCache     []v1.Service
	k8sServicesCacheMu   sync.RWMutex

	clientset *kubernetes.Clientset
)

func main() {
	if nodeName == "" || nodeIP == "" || namespace == "" || lanIfaceName == "" || clusterIfaceName == "" {
		log.Fatal("Missing required environment variables (NODE_NAME, NODE_IP, POD_NAMESPACE, LAN_IFACE, CLUSTER_IFACE)")
	}

	var err error
	lanIface, err = lookupInterface(lanIfaceName)
	if err != nil {
		log.Fatalf("LAN_IFACE %q: %v", lanIfaceName, err)
	}
	clusterIface, err = lookupInterface(clusterIfaceName)
	if err != nil {
		log.Fatalf("CLUSTER_IFACE %q: %v", clusterIfaceName, err)
	}

	log.Printf("LAN interface: %s, Cluster interface: %s", lanIface.Name, clusterIface.Name)

	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}

	clientset, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go browseCluster(ctx)
	go browseLAN(ctx)
	go runConfigMapInformer(ctx)
	go runConfigMapWriter(ctx)
	go runServiceCacheRefresh(ctx)

	waitForShutdown(cancel)
}

func lookupInterface(name string) (net.Interface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return net.Interface{}, fmt.Errorf("interface not found: %w", err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return net.Interface{}, fmt.Errorf("interface %s is not up", name)
	}
	if iface.Flags&net.FlagMulticast == 0 {
		return net.Interface{}, fmt.Errorf("interface %s does not support multicast", name)
	}
	return *iface, nil
}

func waitForShutdown(cancel context.CancelFunc) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	cancel()
}

//
// =====================================================
// Informer-based registry sync
// =====================================================
//

func runConfigMapInformer(ctx context.Context) {
	factory := informers.NewSharedInformerFactoryWithOptions(
		clientset,
		time.Minute,
		informers.WithNamespace(namespace),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", configMapName).String()
		}),
	)

	informer := factory.Core().V1().ConfigMaps().Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    handleConfigMap,
		UpdateFunc: func(_, newObj interface{}) { handleConfigMap(newObj) },
		DeleteFunc: handleConfigMapDelete,
	})

	go factory.Start(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		runtime.HandleError(fmt.Errorf("failed to sync informer cache"))
		return
	}

	<-ctx.Done()
}

func handleConfigMap(obj interface{}) {
	cm, ok := obj.(*v1.ConfigMap)
	if !ok || cm.Name != configMapName {
		return
	}

	activeKeys := map[string]struct{}{}
	for _, raw := range cm.Data {
		var svc ServiceEntry
		if err := json.Unmarshal([]byte(raw), &svc); err != nil {
			continue
		}
		activeKeys[svc.Instance+svc.Service] = struct{}{}
		ensureAdvertised(svc)
	}

	// Shut down advertisements for services no longer in the ConfigMap.
	localMutex.Lock()
	for k, s := range localAds {
		if _, exists := activeKeys[k]; !exists {
			s.Shutdown()
			delete(localAds, k)
		}
	}
	localMutex.Unlock()
}

func handleConfigMapDelete(obj interface{}) {
	localMutex.Lock()
	defer localMutex.Unlock()

	for k, s := range localAds {
		s.Shutdown()
		delete(localAds, k)
	}
}

//
// =====================================================
// mDNS Browsing
// =====================================================
//

func browseLAN(ctx context.Context) {
	resolver, err := zeroconf.NewResolver(zeroconf.SelectIfaces([]net.Interface{lanIface}))
	if err != nil {
		log.Fatal("Failed to create LAN type resolver:", err)
	}
	types := make(chan *zeroconf.ServiceEntry)

	go func() {
		for entry := range types {
			// entry.Instance from _services._dns-sd._udp includes the domain
			// (e.g. "_http._tcp.local") — strip it to get the bare service type.
			serviceType := strings.TrimSuffix(entry.Instance, ".local")
			startInstanceBrowser(ctx, serviceType, lanIface, handleLANService)
		}
	}()

	resolver.Browse(ctx, "_services._dns-sd._udp", "local.", types)
}

func browseCluster(ctx context.Context) {
	resolver, err := zeroconf.NewResolver(zeroconf.SelectIfaces([]net.Interface{clusterIface}))
	if err != nil {
		log.Fatal("Failed to create cluster type resolver:", err)
	}
	types := make(chan *zeroconf.ServiceEntry)

	go func() {
		for entry := range types {
			serviceType := strings.TrimSuffix(entry.Instance, ".local")
			startInstanceBrowser(ctx, serviceType, clusterIface, handleClusterService)
		}
	}()

	resolver.Browse(ctx, "_services._dns-sd._udp", "local.", types)
}

// startInstanceBrowser starts a Browse for actual service instances of a given
// service type on the specified interface. Deduplicates by (iface, serviceType).
func startInstanceBrowser(ctx context.Context, serviceType string, iface net.Interface, handler func(*zeroconf.ServiceEntry)) {
	key := iface.Name + "/" + serviceType

	browsersMutex.Lock()
	if _, exists := activeBrowsers[key]; exists {
		browsersMutex.Unlock()
		return
	}
	activeBrowsers[key] = struct{}{}
	browsersMutex.Unlock()

	log.Printf("Browsing %s on %s", serviceType, iface.Name)

	go func() {
		resolver, err := zeroconf.NewResolver(zeroconf.SelectIfaces([]net.Interface{iface}))
		if err != nil {
			log.Printf("Failed to create resolver for %s on %s: %v", serviceType, iface.Name, err)
			return
		}
		entries := make(chan *zeroconf.ServiceEntry)
		go func() {
			for entry := range entries {
				handler(entry)
			}
		}()
		resolver.Browse(ctx, serviceType, "local.", entries)
	}()
}

func handleLANService(entry *zeroconf.ServiceEntry) {
	if hasOrigin(entry.Text) {
		return
	}

	svc := convert(entry)
	svc.Origin = nodeName
	svc.Source = "lan"

	storeService(svc)
}

func handleClusterService(entry *zeroconf.ServiceEntry) {
	if hasOrigin(entry.Text) {
		return
	}

	svc := convert(entry)
	svc.Origin = nodeName
	svc.Source = "cluster"

	// Use the MetalLB LoadBalancer IP if a matching Service exists; fall back to node IP.
	if ip := lookupLoadBalancerIP(entry); ip != "" {
		svc.IPs = []string{ip}
	} else {
		svc.IPs = []string{nodeIP}
	}

	storeService(svc)
}

// runServiceCacheRefresh refreshes the cached list of LoadBalancer services
// every 30 seconds so lookupLoadBalancerIP never hits the API per-event.
func runServiceCacheRefresh(ctx context.Context) {
	refresh := func() {
		svcs, err := clientset.CoreV1().Services("").List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			log.Println("Failed to refresh services cache:", err)
			return
		}
		k8sServicesCacheMu.Lock()
		k8sServicesCache = svcs.Items
		k8sServicesCacheMu.Unlock()
	}

	refresh() // populate immediately on startup
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}

func lookupLoadBalancerIP(entry *zeroconf.ServiceEntry) string {
	k8sServicesCacheMu.RLock()
	svcs := k8sServicesCache
	k8sServicesCacheMu.RUnlock()

	for _, svc := range svcs {
		if svc.Spec.Type != v1.ServiceTypeLoadBalancer {
			continue
		}
		if len(svc.Status.LoadBalancer.Ingress) == 0 {
			continue
		}
		ip := svc.Status.LoadBalancer.Ingress[0].IP
		if ip == "" {
			continue
		}
		if !strings.EqualFold(svc.Name, entry.Instance) {
			continue
		}
		for _, port := range svc.Spec.Ports {
			if int(port.Port) == entry.Port {
				return ip
			}
		}
	}

	return ""
}

//
// =====================================================
// Registry write
// =====================================================
//

// storeService buffers the service entry in memory. The actual ConfigMap write
// is batched by runConfigMapWriter to avoid per-discovery API calls.
func storeService(svc ServiceEntry) {
	data, _ := json.Marshal(svc)
	key := svc.Instance + "-" + svc.Service

	pendingMutex.Lock()
	pendingServices[key] = string(data)
	pendingDirty = true
	pendingMutex.Unlock()
}

// runConfigMapWriter flushes all pending service entries to the ConfigMap in a
// single API call every 2 seconds, keeping API traffic minimal.
func runConfigMapWriter(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			flushPendingServices()
		}
	}
}

// pruneStaleServices removes entries from pendingServices that haven't been
// re-announced within the TTL, indicating the service has gone away.
func pruneStaleServices() {
	const ttl = 3 * time.Minute
	cutoff := time.Now().Add(-ttl).Unix()

	pendingMutex.Lock()
	defer pendingMutex.Unlock()

	for k, raw := range pendingServices {
		var svc ServiceEntry
		if err := json.Unmarshal([]byte(raw), &svc); err != nil || svc.Timestamp < cutoff {
			delete(pendingServices, k)
			pendingDirty = true
		}
	}
}

func flushPendingServices() {
	pruneStaleServices()

	pendingMutex.Lock()
	if !pendingDirty {
		pendingMutex.Unlock()
		return
	}
	snapshot := make(map[string]string, len(pendingServices))
	for k, v := range pendingServices {
		snapshot[k] = v
	}
	pendingDirty = false
	pendingMutex.Unlock()

	for {
		cm, err := clientset.CoreV1().ConfigMaps(namespace).
			Get(context.TODO(), configMapName, metav1.GetOptions{})

		if err != nil {
			newCM := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: namespace,
				},
				Data: snapshot,
			}
			_, err = clientset.CoreV1().ConfigMaps(namespace).
				Create(context.TODO(), newCM, metav1.CreateOptions{})
		} else {
			if cm.Data == nil {
				cm.Data = map[string]string{}
			}
			// Replace this node's entries wholesale so removals propagate.
			for k, raw := range cm.Data {
				var svc ServiceEntry
				if json.Unmarshal([]byte(raw), &svc) == nil && svc.Origin == nodeName {
					delete(cm.Data, k)
				}
			}
			for k, v := range snapshot {
				cm.Data[k] = v
			}
			_, err = clientset.CoreV1().ConfigMaps(namespace).
				Update(context.TODO(), cm, metav1.UpdateOptions{})
		}

		if err == nil {
			return
		}

		time.Sleep(100 * time.Millisecond)
	}
}

//
// =====================================================
// Advertisement control
// =====================================================
//

func ensureAdvertised(svc ServiceEntry) {
	key := svc.Instance + svc.Service

	localMutex.Lock()
	defer localMutex.Unlock()

	if _, exists := localAds[key]; exists {
		return
	}

	// Advertise on the opposite interface from where the service was discovered:
	// LAN-discovered services → advertise on cluster interface
	// Cluster-discovered services → advertise on LAN interface
	var ifaces []net.Interface
	switch svc.Source {
	case "lan":
		ifaces = []net.Interface{clusterIface}
	case "cluster":
		ifaces = []net.Interface{lanIface}
	default:
		log.Printf("Unknown source %q for service %s, skipping", svc.Source, key)
		return
	}

	server, err := zeroconf.RegisterProxy(
		svc.Instance,
		svc.Service,
		svc.Domain,
		svc.Port,
		"proxy.local.",
		svc.IPs,
		append(svc.TXT, "origin="+svc.Origin),
		ifaces,
	)

	if err != nil {
		log.Println("Advertise failed:", err)
		return
	}

	localAds[key] = server
}

//
// =====================================================
// Helpers
// =====================================================
//

func convert(e *zeroconf.ServiceEntry) ServiceEntry {
	ips := []string{}
	for _, ip := range e.AddrIPv4 {
		ips = append(ips, ip.String())
	}

	return ServiceEntry{
		Instance:  e.Instance,
		Service:   e.Service,
		Domain:    e.Domain,
		Port:      e.Port,
		IPs:       ips,
		TXT:       e.Text,
		Timestamp: time.Now().Unix(),
	}
}

func hasOrigin(txt []string) bool {
	for _, t := range txt {
		if len(t) > 7 && t[:7] == "origin=" {
			return true
		}
	}
	return false
}
