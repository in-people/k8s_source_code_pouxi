# 完善Extension apiserver config

cmd/kube-apiserver/app/server.go

```go
func Run(ctx context.Context, opts options.CompletedOptions) error {
	// To help debugging, immediately log version
	klog.Infof("Version: %+v", utilversion.Get())

	klog.InfoS("Golang settings", "GOGC", os.Getenv("GOGC"), "GOMAXPROCS", os.Getenv("GOMAXPROCS"), "GOTRACEBACK", os.Getenv("GOTRACEBACK"))

	config, err := NewConfig(opts)
	if err != nil {
		return err
	}
	completed, err := config.Complete()
	if err != nil {
		return err
	}
	server, err := CreateServerChain(completed)
	if err != nil {
		return err
	}

	prepared, err := server.PrepareRun()
	if err != nil {
		return err
	}

	return prepared.Run(ctx)
}
```


```go
config, err := NewConfig(opts)
	if err != nil {
		return err
	}
```

cmd/kube-apiserver/app/config.go

config, err := NewConfig(opts)

Config的结构体

```go
type Config struct {
	Options options.CompletedOptions

	Aggregator    *aggregatorapiserver.Config
	KubeAPIs      *controlplane.Config
	ApiExtensions *apiextensionsapiserver.Config

	ExtraConfig
}
```

```go
// NewConfig creates all the resources for running kube-apiserver, but runs none of them.
// 创建完整的Config对象，包含运行kube-apiserver所需的所有子系统的配置
// Generic Config (共享基础设施)   
// │  - Storage (etcd)              
// │  - Authentication/Authorization  
// │  - Informers                       
// │  - OpenAPI
func NewConfig(opts options.CompletedOptions) (*Config, error) {
	c := &Config{
		Options: opts,
	}

	// 1 创建通用配置
	genericConfig, versionedInformers, storageFactory, err := controlplaneapiserver.BuildGenericConfig(
		opts.CompletedOptions,
		[]*runtime.Scheme{legacyscheme.Scheme, apiextensionsapiserver.Scheme, aggregatorscheme.Scheme},
		controlplane.DefaultAPIResourceConfigSource(),
		generatedopenapi.GetOpenAPIDefinitions,
	)
	if err != nil {
		return nil, err
	}

	// 2 创建核心kube API Server config 配置  用于处理pod、deployment、service等核心资源
	kubeAPIs, serviceResolver, pluginInitializer, err := CreateKubeAPIServerConfig(opts, genericConfig, versionedInformers, storageFactory)
	if err != nil {
		return nil, err
	}
	c.KubeAPIs = kubeAPIs

	// 3 创建API Extensions配置 用于配置CRD（自定义资源定义）系统
	apiExtensions, err := controlplaneapiserver.CreateAPIExtensionsConfig(*kubeAPIs.ControlPlane.Generic, kubeAPIs.ControlPlane.VersionedInformers, pluginInitializer, opts.CompletedOptions, opts.MasterCount,
		serviceResolver, webhook.NewDefaultAuthenticationInfoResolverWrapper(kubeAPIs.ControlPlane.ProxyTransport, kubeAPIs.ControlPlane.Generic.EgressSelector, kubeAPIs.ControlPlane.Generic.LoopbackClientConfig, kubeAPIs.ControlPlane.Generic.TracerProvider))
	if err != nil {
		return nil, err
	}
	c.ApiExtensions = apiExtensions

	// 4 创建API Aggregator配置  配置API聚合层
	aggregator, err := controlplaneapiserver.CreateAggregatorConfig(*kubeAPIs.ControlPlane.Generic, opts.CompletedOptions, kubeAPIs.ControlPlane.VersionedInformers, serviceResolver, kubeAPIs.ControlPlane.ProxyTransport, kubeAPIs.ControlPlane.Extra.PeerProxy, pluginInitializer)
	if err != nil {
		return nil, err
	}
	c.Aggregator = aggregator

	return c, nil
}
```

### BuildGenericConfig 创建通用的API Server配置

pkg/controlplane/apiserver/config.go

返回：通用的API Server配置、共享的Informer工厂、存储工厂

```go
// BuildGenericConfig takes the generic controlplane apiserver options and produces
// the genericapiserver.Config associated with it. The genericapiserver.Config is
// often shared between multiple delegated apiservers.
func BuildGenericConfig(
	s options.CompletedOptions,
	schemes []*runtime.Scheme,
	resourceConfig *serverstorage.ResourceConfig,
	getOpenAPIDefinitions func(ref openapicommon.ReferenceCallback) map[string]openapicommon.OpenAPIDefinition,
) (
	genericConfig *genericapiserver.Config,
	versionedInformers clientgoinformers.SharedInformerFactory,
	storageFactory *serverstorage.DefaultStorageFactory,
	lastErr error,
) {
        // 1 创建基础配置
	genericConfig = genericapiserver.NewConfig(legacyscheme.Codecs)
	genericConfig.Flagz = s.Flagz
	genericConfig.MergedResourceConfig = resourceConfig

        // 2 应用各类配置选项
	if lastErr = s.GenericServerRunOptions.ApplyTo(genericConfig); lastErr != nil {
		return
	}

	if lastErr = s.SecureServing.ApplyTo(&genericConfig.SecureServing, &genericConfig.LoopbackClientConfig); lastErr != nil {
		return
	}

        // 3 配置回环通信
	// Use protobufs for self-communication.
	// Since not every generic apiserver has to support protobufs, we
	// cannot default to it in generic apiserver and need to explicitly
	// set it in kube-apiserver.
	genericConfig.LoopbackClientConfig.ContentConfig.ContentType = "application/vnd.kubernetes.protobuf"
	// Disable compression for self-communication, since we are going to be
	// on a fast local network
	genericConfig.LoopbackClientConfig.DisableCompression = true

        // 创建client和Informer
	kubeClientConfig := genericConfig.LoopbackClientConfig
	clientgoExternalClient, err := clientgoclientset.NewForConfig(kubeClientConfig)
	if err != nil {
		lastErr = fmt.Errorf("failed to create real external clientset: %w", err)
		return
	}
	trim := func(obj interface{}) (interface{}, error) {
		if accessor, err := meta.Accessor(obj); err == nil && accessor.GetManagedFields() != nil {
			accessor.SetManagedFields(nil)
		}
		return obj, nil
	}
	versionedInformers = clientgoinformers.NewSharedInformerFactoryWithOptions(clientgoExternalClient, 10*time.Minute, clientgoinformers.WithTransform(trim))

	if lastErr = s.Features.ApplyTo(genericConfig, clientgoExternalClient, versionedInformers); lastErr != nil {
		return
	}
	if lastErr = s.APIEnablement.ApplyTo(genericConfig, resourceConfig, legacyscheme.Scheme); lastErr != nil {
		return
	}
	if lastErr = s.EgressSelector.ApplyTo(genericConfig); lastErr != nil {
		return
	}
	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIServerTracing) {
		if lastErr = s.Traces.ApplyTo(genericConfig.EgressSelector, genericConfig); lastErr != nil {
			return
		}
	}

        // 6 配置 OpenAPI
	// wrap the definitions to revert any changes from disabled features
	getOpenAPIDefinitions = openapi.GetOpenAPIDefinitionsWithoutDisabledFeatures(getOpenAPIDefinitions)
	namer := openapinamer.NewDefinitionNamer(schemes...)
	genericConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(getOpenAPIDefinitions, namer)
	genericConfig.OpenAPIConfig.Info.Title = "Kubernetes"
	genericConfig.OpenAPIV3Config = genericapiserver.DefaultOpenAPIV3Config(getOpenAPIDefinitions, namer)
	genericConfig.OpenAPIV3Config.Info.Title = "Kubernetes"

	genericConfig.LongRunningFunc = filters.BasicLongRunningRequestCheck(
		sets.NewString("watch", "proxy"),
		sets.NewString("attach", "exec", "proxy", "log", "portforward"),
	)

	if genericConfig.EgressSelector != nil {
		s.Etcd.StorageConfig.Transport.EgressLookup = genericConfig.EgressSelector.Lookup
	}
	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIServerTracing) {
		s.Etcd.StorageConfig.Transport.TracerProvider = genericConfig.TracerProvider
	} else {
		s.Etcd.StorageConfig.Transport.TracerProvider = noopoteltrace.NewTracerProvider()
	}
  
        // 创建存储工厂
	storageFactoryConfig := kubeapiserver.NewStorageFactoryConfigEffectiveVersion(genericConfig.EffectiveVersion)
	storageFactoryConfig.APIResourceConfig = genericConfig.MergedResourceConfig
	storageFactoryConfig.DefaultResourceEncoding.SetEffectiveVersion(genericConfig.EffectiveVersion)
	storageFactory, lastErr = storageFactoryConfig.Complete(s.Etcd).New()
	if lastErr != nil {
		return
	}
	// storageFactory.StorageConfig is copied from etcdOptions.StorageConfig,
	// the StorageObjectCountTracker is still nil. Here we copy from genericConfig.
	storageFactory.StorageConfig.StorageObjectCountTracker = genericConfig.StorageObjectCountTracker
	if lastErr = s.Etcd.ApplyWithStorageFactoryTo(storageFactory, genericConfig); lastErr != nil {
		return
	}

	ctx := wait.ContextForChannel(genericConfig.DrainedNotify())
  
        // 配置认证授权
	// Authentication.ApplyTo requires already applied OpenAPIConfig and EgressSelector if present
	if lastErr = s.Authentication.ApplyTo(ctx, &genericConfig.Authentication, genericConfig.SecureServing, genericConfig.EgressSelector, genericConfig.OpenAPIConfig, genericConfig.OpenAPIV3Config, clientgoExternalClient, versionedInformers, genericConfig.APIServerID); lastErr != nil {
		return
	}

	var enablesRBAC bool
	genericConfig.Authorization.Authorizer, genericConfig.RuleResolver, enablesRBAC, err = BuildAuthorizer(
		ctx,
		s,
		genericConfig.EgressSelector,
		genericConfig.APIServerID,
		versionedInformers,
	)
	if err != nil {
		lastErr = fmt.Errorf("invalid authorization config: %w", err)
		return
	}
	if s.Authorization != nil && !enablesRBAC {
		genericConfig.DisabledPostStartHooks.Insert(rbacrest.PostStartHookName)
	}
  
        // 9 配置审计
	lastErr = s.Audit.ApplyTo(genericConfig)
	if lastErr != nil {
		return
	}

	genericConfig.AggregatedDiscoveryGroupManager = aggregated.NewResourceManager("apis")

	if genericConfig.EnableServiceQuality {
		genericConfig.ServiceQualityConfig = filters.NewQoSConfig(clientgoExternalClient, versionedInformers)
	}

	return
}
```

```go
type ServerRunOptions struct {
	AdvertiseAddress net.IP

	CorsAllowedOriginList        []string
	HSTSDirectives               []string
	ExternalHost                 string
	MaxRequestsInFlight          int
	MaxMutatingRequestsInFlight  int
	RequestTimeout               time.Duration
	GoawayChance                 float64
	LivezGracePeriod             time.Duration
	MinRequestTimeout            int
	StorageInitializationTimeout time.Duration
	ShutdownDelayDuration        time.Duration
	// We intentionally did not add a flag for this option. Users of the
	// apiserver library can wire it to a flag.
	JSONPatchMaxCopyBytes int64
	// The limit on the request body size that would be accepted and
	// decoded in a write request. 0 means no limit.
	// We intentionally did not add a flag for this option. Users of the
	// apiserver library can wire it to a flag.
	MaxRequestBodyBytes  int64
	EnableServiceQuality bool

	// ShutdownSendRetryAfter dictates when to initiate shutdown of the HTTP
	// Server during the graceful termination of the apiserver. If true, we wait
	// for non longrunning requests in flight to be drained and then initiate a
	// shutdown of the HTTP Server. If false, we initiate a shutdown of the HTTP
	// Server as soon as ShutdownDelayDuration has elapsed.
	// If enabled, after ShutdownDelayDuration elapses, any incoming request is
	// rejected with a 429 status code and a 'Retry-After' response.
	ShutdownSendRetryAfter bool

	// ShutdownWatchTerminationGracePeriod, if set to a positive value,
	// is the maximum duration the apiserver will wait for all active
	// watch request(s) to drain.
	// Once this grace period elapses, the apiserver will no longer
	// wait for any active watch request(s) in flight to drain, it will
	// proceed to the next step in the graceful server shutdown process.
	// If set to a positive value, the apiserver will keep track of the
	// number of active watch request(s) in flight and during shutdown
	// it will wait, at most, for the specified duration and allow these
	// active watch requests to drain with some rate limiting in effect.
	// The default is zero, which implies the apiserver will not keep
	// track of active watch request(s) in flight and will not wait
	// for them to drain, this maintains backward compatibility.
	// This grace period is orthogonal to other grace periods, and
	// it is not overridden by any other grace period.
	ShutdownWatchTerminationGracePeriod time.Duration

	// ComponentGlobalsRegistry is the registry where the effective versions and feature gates for all components are stored.
	ComponentGlobalsRegistry basecompatibility.ComponentGlobalsRegistry
	// ComponentName is name under which the server's global variabled are registered in the ComponentGlobalsRegistry.
	ComponentName string
	// EmulationForwardCompatible is an option to implicitly enable all APIs which are introduced after the emulation version and
	// have higher priority than APIs of the same group resource enabled at the emulation version.
	// If true, all APIs that have higher priority than the APIs(beta+) of the same group resource enabled at the emulation version will be installed.
	// This is needed when a controller implementation migrates to newer API versions, for the binary version, and also uses the newer API versions even when emulation version is set.
	// Not applicable to alpha APIs.
	EmulationForwardCompatible bool
	// RuntimeConfigEmulationForwardCompatible is an option to explicitly enable specific APIs introduced after the emulation version through the runtime-config.
	// If true, APIs identified by group/version that are enabled in the --runtime-config flag will be installed even if it is introduced after the emulation version. --runtime-config flag values that identify multiple APIs, such as api/all,api/ga,api/beta, are not influenced by this flag and will only enable APIs available at the current emulation version.
	// If false, error would be thrown if any GroupVersion or GroupVersionResource explicitly enabled in the --runtime-config flag is introduced after the emulation version.
	RuntimeConfigEmulationForwardCompatible bool
}
```

## 创建aggregator server config

```go

	aggregator, err := controlplaneapiserver.CreateAggregatorConfig(*kubeAPIs.ControlPlane.Generic, opts.CompletedOptions, kubeAPIs.ControlPlane.VersionedInformers, serviceResolver, kubeAPIs.ControlPlane.ProxyTransport, kubeAPIs.ControlPlane.Extra.PeerProxy, pluginInitializer)


// Kubernetes 中创建 Aggregator API Server 配置 的函数。Aggregator 是负责聚合自定义 API 服务器（如 CRD、Metrics Server等）的核心组件。

func CreateAggregatorConfig(
	kubeAPIServerConfig genericapiserver.Config,
	commandOptions options.CompletedOptions,
	externalInformers kubeexternalinformers.SharedInformerFactory,
	serviceResolver aggregatorapiserver.ServiceResolver,
	proxyTransport *http.Transport,
	peerProxy utilpeerproxy.Interface,
	pluginInitializers []admission.PluginInitializer,
) (*aggregatorapiserver.Config, error) {
	// make a shallow copy to let us twiddle a few things
	// most of the config actually remains the same.  We only need to mess with a couple items related to the particulars of the aggregator
	genericConfig := kubeAPIServerConfig
	genericConfig.PostStartHooks = map[string]genericapiserver.PostStartHookConfigEntry{}
	genericConfig.RESTOptionsGetter = nil
	// prevent generic API server from installing the OpenAPI handler. Aggregator server
	// has its own customized OpenAPI handler.
	genericConfig.SkipOpenAPIInstallation = true

	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.StorageVersionAPI) &&
		utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIServerIdentity) {
		// Add StorageVersionPrecondition handler to aggregator-apiserver.
		// The handler will block write requests to built-in resources until the
		// target resources' storage versions are up-to-date.
		genericConfig.BuildHandlerChainFunc = genericapiserver.BuildHandlerChainWithStorageVersionPrecondition
	}

	if peerProxy != nil {
		originalHandlerChainBuilder := genericConfig.BuildHandlerChainFunc
		genericConfig.BuildHandlerChainFunc = func(apiHandler http.Handler, c *genericapiserver.Config) http.Handler {
			// Add peer proxy handler to aggregator-apiserver.
			// wrap the peer proxy handler first.
			apiHandler = peerProxy.WrapHandler(apiHandler)
			return originalHandlerChainBuilder(apiHandler, c)
		}
	}

	// copy the etcd options so we don't mutate originals.
	// we assume that the etcd options have been completed already.  avoid messing with anything outside
	// of changes to StorageConfig as that may lead to unexpected behavior when the options are applied.
	etcdOptions := *commandOptions.Etcd
	etcdOptions.StorageConfig.Codec = aggregatorscheme.Codecs.LegacyCodec(v1.SchemeGroupVersion, v1beta1.SchemeGroupVersion)
	etcdOptions.StorageConfig.EncodeVersioner = runtime.NewMultiGroupVersioner(v1.SchemeGroupVersion, schema.GroupKind{Group: v1beta1.GroupName})
	etcdOptions.SkipHealthEndpoints = true // avoid double wiring of health checks
	if err := etcdOptions.ApplyTo(&genericConfig); err != nil {
		return nil, err
	}

	// override MergedResourceConfig with aggregator defaults and registry
	if err := commandOptions.APIEnablement.ApplyTo(
		&genericConfig,
		aggregatorapiserver.DefaultAPIResourceConfigSource(),
		aggregatorscheme.Scheme); err != nil {
		return nil, err
	}

	aggregatorConfig := &aggregatorapiserver.Config{
		GenericConfig: &genericapiserver.RecommendedConfig{
			Config:                genericConfig,
			SharedInformerFactory: externalInformers,
		},
		ExtraConfig: aggregatorapiserver.ExtraConfig{
			ProxyClientCertFile:       commandOptions.ProxyClientCertFile,
			ProxyClientKeyFile:        commandOptions.ProxyClientKeyFile,
			PeerAdvertiseAddress:      commandOptions.PeerAdvertiseAddress,
			ServiceResolver:           serviceResolver, // 解析API Service的后端服务
			ProxyTransport:            proxyTransport,  // 代理到后端的 HTTP 传输
			RejectForwardingRedirects: commandOptions.AggregatorRejectForwardingRedirects,
		},
	}

	// we need to clear the poststarthooks so we don't add them multiple times to all the servers (that fails)
	aggregatorConfig.GenericConfig.PostStartHooks = map[string]genericapiserver.PostStartHookConfigEntry{}

	return aggregatorConfig, nil
}
```


### aggregator.complete()

cmd/kube-apiserver/app/config.go

```go
func (c *Config) Complete() (CompletedConfig, error) {
	return CompletedConfig{&completedConfig{
		Options: c.Options,

		Aggregator:    c.Aggregator.Complete(),
		KubeAPIs:      c.KubeAPIs.Complete(),
		ApiExtensions: c.ApiExtensions.Complete(),

		ExtraConfig: c.ExtraConfig,
	}}, nil
}
```

```go
func (cfg *Config) Complete() CompletedConfig {
	c := completedConfig{
		cfg.GenericConfig.Complete(),
		&cfg.ExtraConfig,
	}

	c.GenericConfig.EnableDiscovery = false

	return CompletedConfig{&c}
}

```

```go
// k8s api server配置的complete()方法，用于填充未设置但必须的配置字段
func (c *Config) Complete(informers informers.SharedInformerFactory) CompletedConfig {
	if c.FeatureGate == nil {
		c.FeatureGate = utilfeature.DefaultFeatureGate
	}
	if len(c.ExternalAddress) == 0 && c.PublicAddress != nil {
		c.ExternalAddress = c.PublicAddress.String()
	}

	// if there is no port, and we listen on one securely, use that one
	if _, _, err := net.SplitHostPort(c.ExternalAddress); err != nil {
		if c.SecureServing == nil {
			klog.Fatalf("cannot derive external address port without listening on a secure port.")
		}
		_, port, err := c.SecureServing.HostPort()
		if err != nil {
			klog.Fatalf("cannot derive external address from the secure port: %v", err)
		}
		c.ExternalAddress = net.JoinHostPort(c.ExternalAddress, strconv.Itoa(port))
	}
	completeOpenAPI(c.OpenAPIConfig, c.EffectiveVersion.EmulationVersion())
	completeOpenAPIV3(c.OpenAPIV3Config, c.EffectiveVersion.EmulationVersion())

	if c.DiscoveryAddresses == nil {
		c.DiscoveryAddresses = discovery.DefaultAddresses{DefaultAddress: c.ExternalAddress}
	}

	AuthorizeClientBearerToken(c.LoopbackClientConfig, &c.Authentication, &c.Authorization)

	if c.RequestInfoResolver == nil {
		c.RequestInfoResolver = NewRequestInfoResolver(c)
	}

	if c.EquivalentResourceRegistry == nil {
		if c.RESTOptionsGetter == nil {
			c.EquivalentResourceRegistry = runtime.NewEquivalentResourceRegistry()
		} else {
			c.EquivalentResourceRegistry = runtime.NewEquivalentResourceRegistryWithIdentity(func(groupResource schema.GroupResource) string {
				// use the storage prefix as the key if possible
				if opts, err := c.RESTOptionsGetter.GetRESTOptions(groupResource, nil); err == nil {
					return opts.ResourcePrefix
				}
				// otherwise return "" to use the default key (parent GV name)
				return ""
			})
		}
	}

	return CompletedConfig{&completedConfig{c, informers}}
}
```

# 创建 Aggregator Server 实例

```go
aggregatorServer, err := controlplaneapiserver.CreateAggregatorServer(config.Aggregator, nativeAPIs.GenericAPIServer, apiExtensionsServer.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdAPIEnabled, controlplaneapiserver.DefaultGenericAPIServicePriorities())

// 创建聚合API Server的核心函数

// 1. 构建聚合层：创建能够聚合多个 API service 的聚合 server
// 2. 自动化管理：通过控制器自动管理 APIService 的注册和删除
// 3. 协调启动顺序：确保 CRD 和 APIService 的初始化按正确顺序执行
func CreateAggregatorServer(aggregatorConfig aggregatorapiserver.CompletedConfig, delegateAPIServer genericapiserver.DelegationTarget, crds apiextensionsinformers.CustomResourceDefinitionInformer, crdAPIEnabled bool, apiVersionPriorities map[schema.GroupVersion]APIServicePriority) (*aggregatorapiserver.APIAggregator, error) {
	//
	aggregatorServer, err := aggregatorConfig.NewWithDelegate(delegateAPIServer)
	if err != nil {
		return nil, err
	}

	// create controllers for auto-registration
	// 创建自动注册客户端和控制器
	apiRegistrationClient, err := apiregistrationclient.NewForConfig(aggregatorConfig.GenericConfig.LoopbackClientConfig)
	if err != nil {
		return nil, err
	}
	// 创建自动注册客户端。 负责自动将新的API资源注册为API Service
	autoRegistrationController := autoregister.NewAutoRegisterController(aggregatorServer.APIRegistrationInformers.Apiregistration().V1().APIServices(), apiRegistrationClient)
	apiServices := apiServicesToRegister(delegateAPIServer, autoRegistrationController, apiVersionPriorities)

	type controller interface {
		Run(workers int, stopCh <-chan struct{})
		WaitForInitialSync()
	}

	// 创建CRD注册controller
	// 如果启用了CRD API，创建CRD注册控制器
	// 监听CRD的变化，并自动为CRD创建对应的API Service
	var crdRegistrationController controller
	if crdAPIEnabled {
		crdRegistrationController = crdregistration.NewCRDRegistrationController(
			crds,
			autoRegistrationController)
	}

	// Imbue all builtin group-priorities onto the aggregated discovery
	if aggregatorConfig.GenericConfig.AggregatedDiscoveryGroupManager != nil {
		for gv, entry := range apiVersionPriorities {
			aggregatorConfig.GenericConfig.AggregatedDiscoveryGroupManager.SetGroupVersionPriority(metav1.GroupVersion(gv), int(entry.Group), int(entry.Version))
		}
	}

	// 启动控制器
	err = aggregatorServer.GenericAPIServer.AddPostStartHook("kube-apiserver-autoregistration", func(context genericapiserver.PostStartHookContext) error {
		if crdAPIEnabled {
			go crdRegistrationController.Run(5, context.Done())
		}
		go func() {
			// let the CRD controller process the initial set of CRDs before starting the autoregistration controller.
			// this prevents the autoregistration controller's initial sync from deleting APIServices for CRDs that still exist.
			// we only need to do this if CRDs are enabled on this server.  We can't use discovery because we are the source for discovery.
			if crdAPIEnabled {
				klog.Infof("waiting for initial CRD sync...")
				crdRegistrationController.WaitForInitialSync()
				klog.Infof("initial CRD sync complete...")
			} else {
				klog.Infof("CRD API not enabled, starting APIService registration without waiting for initial CRD sync")
			}
			autoRegistrationController.Run(5, context.Done())
		}()
		return nil
	})
	if err != nil {
		return nil, err
	}

	err = aggregatorServer.GenericAPIServer.AddBootSequenceHealthChecks(
		makeAPIServiceAvailableHealthCheck(
			"autoregister-completion",
			apiServices,
			aggregatorServer.APIRegistrationInformers.Apiregistration().V1().APIServices(),
		),
	)
	if err != nil {
		return nil, err
	}

	return aggregatorServer, nil
}


```


## NewWithDelegate 创建APIAggregator()

```go

// 这个函数的核心职责是：

//   1. 构建基础设施：创建 GenericAPIServer、Informers、客户端
//   2. 路由配置：设置 /apis 端点和代理处理器
//   3. 控制器编排：创建多个控制器，并通过 PostStartHook 精确控制启动顺序
//   4. 健康检查：通过可用性控制器监控本地和远程 APIService 的健康状态
//   5. 发现管理：聚合所有 APIService 的 API 发现信息

//   启动顺序保证（通过 channel 同步）：
//   Informer 启动
//     ↓
//   APIService 注册控制器完成
//     ↓
//   发现聚合控制器同步完成
//     ↓
//   Storage 版本更新完成
//     ↓
//   Server 完全就绪

//   这种设计确保了聚合层在处理流量前，所有必要的初始化工作都已完成，避免了 404 错误和路由问题。

// NewWithDelegate returns a new instance of APIAggregator from the given config.
func (c completedConfig) NewWithDelegate(delegationTarget genericapiserver.DelegationTarget) (*APIAggregator, error) {
	genericServer, err := c.GenericConfig.New("kube-aggregator", delegationTarget)
	if err != nil {
		return nil, err
	}

	// 2 创建API Registration相关组件
	// 创建访问 apiregistration.k8s.io API的client（用于管理APIService）
	apiregistrationClient, err := clientset.NewForConfig(c.GenericConfig.LoopbackClientConfig)
	if err != nil {
		return nil, err
	}

	// 创建共享informer工厂，监听APIService资源变化
	informerFactory := informers.NewSharedInformerFactory(
		apiregistrationClient,
		5*time.Minute, // this is effectively used as a refresh interval right now.  Might want to do something nicer later on.
	)

	// apiServiceRegistrationControllerInitiated is closed when APIServiceRegistrationController has finished "installing" all known APIServices.
	// At this point we know that the proxy handler knows about APIServices and can handle client requests.
	// Before it might have resulted in a 404 response which could have serious consequences for some controllers like  GC and NS
	//
	// Note that the APIServiceRegistrationController waits for APIServiceInformer to synced before doing its work.
	// - 这确保在 APIService 注册完成之前，server 不会标记为完全就绪
	// - 重要：防止 GC 和 Namespace Controller 等组件收到 404 响应
	apiServiceRegistrationControllerInitiated := make(chan struct{})
	if err := genericServer.RegisterMuxAndDiscoveryCompleteSignal("APIServiceRegistrationControllerInitiated", apiServiceRegistrationControllerInitiated); err != nil {
		return nil, err
	}

	// 4 配置代理网络传输
	var proxyTransportDial *transport.DialHolder
	if c.GenericConfig.EgressSelector != nil {
		egressDialer, err := c.GenericConfig.EgressSelector.Lookup(egressselector.Cluster.AsNetworkContext())
		if err != nil {
			return nil, err
		}
		if egressDialer != nil {
			proxyTransportDial = &transport.DialHolder{Dial: egressDialer}
		}
	} else if c.ExtraConfig.ProxyTransport != nil && c.ExtraConfig.ProxyTransport.DialContext != nil {
		proxyTransportDial = &transport.DialHolder{Dial: c.ExtraConfig.ProxyTransport.DialContext}
	}

	s := &APIAggregator{
		GenericAPIServer:           genericServer,
		delegateHandler:            delegationTarget.UnprotectedHandler(),
		proxyTransportDial:         proxyTransportDial, // 缓存每个API Service的代理处理器
		proxyHandlers:              map[string]*proxyHandler{},
		handledGroupVersions:       map[string]sets.Set[string]{},
		lister:                     informerFactory.Apiregistration().V1().APIServices().Lister(),
		APIRegistrationInformers:   informerFactory,
		serviceResolver:            c.ExtraConfig.ServiceResolver, // 服务解析器，将API Service解析为后端服务地址
		openAPIConfig:              c.GenericConfig.OpenAPIConfig,
		openAPIV3Config:            c.GenericConfig.OpenAPIV3Config,
		proxyCurrentCertKeyContent: func() (bytes []byte, bytes2 []byte) { return nil, nil },
		rejectForwardingRedirects:  c.ExtraConfig.RejectForwardingRedirects,
		tracerProvider:             c.GenericConfig.TracerProvider,
	}

	// 6 安装APIService REST Storage
	// 安装apiregistration.k8s.io/v1 API组
	// 提供创建、更新、删除APIService资源的REST接口
	apiGroupInfo := apiservicerest.NewRESTStorage(c.GenericConfig.MergedResourceConfig, c.GenericConfig.RESTOptionsGetter, false)
	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

	enabledVersions := sets.NewString()
	for v := range apiGroupInfo.VersionedResourcesStorageMap {
		enabledVersions.Insert(v)
	}
	if !enabledVersions.Has(v1.SchemeGroupVersion.Version) {
		return nil, fmt.Errorf("API group/version %s must be enabled", v1.SchemeGroupVersion.String())
	}

	apisHandler := &apisHandler{
		codecs:         aggregatorscheme.Codecs,
		lister:         s.lister,
		discoveryGroup: discoveryGroup(enabledVersions),
	}

	// 配置 /apis 端点处理器
	apisHandlerWithAggregationSupport := aggregated.WrapAggregatedDiscoveryToHandler(apisHandler, s.GenericAPIServer.AggregatedDiscoveryGroupManager)
	// 设置/apis路径de路由器，提供聚合API的发型
	// 支持聚合发现，将所有APIService的API 信息合并返回
	s.GenericAPIServer.Handler.NonGoRestfulMux.Handle("/apis", apisHandlerWithAggregationSupport)
	s.GenericAPIServer.Handler.NonGoRestfulMux.UnlistedHandle("/apis/", apisHandler)

	// 8 创建APIService注册控制器
	// 核心控制器，负责
	// 监听APIService变化
	// 为每个APIService创建、更新代理处理器
	// 将APIService添加到路由
	apiserviceRegistrationController := NewAPIServiceRegistrationController(informerFactory.Apiregistration().V1().APIServices(), s)
	if len(c.ExtraConfig.ProxyClientCertFile) > 0 && len(c.ExtraConfig.ProxyClientKeyFile) > 0 {
		aggregatorProxyCerts, err := dynamiccertificates.NewDynamicServingContentFromFiles("aggregator-proxy-cert", c.ExtraConfig.ProxyClientCertFile, c.ExtraConfig.ProxyClientKeyFile)
		if err != nil {
			return nil, err
		}
		// We are passing the context to ProxyCerts.RunOnce as it needs to implement RunOnce(ctx) however the
		// context is not used at all. So passing a empty context shouldn't be a problem
		if err := aggregatorProxyCerts.RunOnce(context.Background()); err != nil {
			return nil, err
		}
		aggregatorProxyCerts.AddListener(apiserviceRegistrationController)
		s.proxyCurrentCertKeyContent = aggregatorProxyCerts.CurrentCertKeyContent

		s.GenericAPIServer.AddPostStartHookOrDie("aggregator-reload-proxy-client-cert", func(postStartHookContext genericapiserver.PostStartHookContext) error {
			go aggregatorProxyCerts.Run(postStartHookContext, 1)
			return nil
		})
	}

	s.GenericAPIServer.AddPostStartHookOrDie("start-kube-aggregator-informers", func(context genericapiserver.PostStartHookContext) error {
		informerFactory.Start(context.Done())
		c.GenericConfig.SharedInformerFactory.Start(context.Done())
		return nil
	})

	// create shared (remote and local) availability metrics
	// TODO: decouple from legacyregistry
	metrics := availabilitymetrics.New()
	registerIntoLegacyRegistryOnce.Do(func() { err = metrics.Register(legacyregistry.Register, legacyregistry.CustomRegister) })
	if err != nil {
		return nil, err
	}

	// always run local availability controller
	local, err := localavailability.New(
		informerFactory.Apiregistration().V1().APIServices(),
		apiregistrationClient.ApiregistrationV1(),
		metrics,
	)
	if err != nil {
		return nil, err
	}
	s.GenericAPIServer.AddPostStartHookOrDie("apiservice-status-local-available-controller", func(context genericapiserver.PostStartHookContext) error {
		// if we end up blocking for long periods of time, we may need to increase workers.
		go local.Run(5, context.Done())
		return nil
	})

	// conditionally run remote availability controller. This could be replaced in certain
	// generic controlplane use-cases where there is another concept of services and/or endpoints.
	if !c.ExtraConfig.DisableRemoteAvailableConditionController {
		remote, err := remoteavailability.New(
			informerFactory.Apiregistration().V1().APIServices(),
			c.GenericConfig.SharedInformerFactory.Core().V1().Services(),
			c.GenericConfig.SharedInformerFactory.Discovery().V1().EndpointSlices(),
			apiregistrationClient.ApiregistrationV1(),
			proxyTransportDial,
			(func() ([]byte, []byte))(s.proxyCurrentCertKeyContent),
			s.serviceResolver,
			metrics,
		)
		if err != nil {
			return nil, err
		}
		//
		s.GenericAPIServer.AddPostStartHookOrDie("apiservice-status-remote-available-controller", func(context genericapiserver.PostStartHookContext) error {
			// if we end up blocking for long periods of time, we may need to increase workers.
			go remote.Run(5, context.Done())
			return nil
		})
	}

	// 12 运行注册控制器
	s.GenericAPIServer.AddPostStartHookOrDie("apiservice-registration-controller", func(context genericapiserver.PostStartHookContext) error {
		go apiserviceRegistrationController.Run(context.Done(), apiServiceRegistrationControllerInitiated)
		select {
		case <-context.Done():
		case <-apiServiceRegistrationControllerInitiated:
		}

		return nil
	})

	s.discoveryAggregationController = NewDiscoveryManager(
		// Use aggregator as the source name to avoid overwriting native/CRD
		// groups
		s.GenericAPIServer.AggregatedDiscoveryGroupManager.WithSource(aggregated.AggregatorSource),
	)

	// Setup discovery endpoint
	// 创建发现管理器，负责将所有 APIService 的 API 信息聚合到发现文档中
	// 	- 启动顺序保证：
	//     a. 等待 APIService 注册控制器完成
	//     b. 启动发现聚合控制器
	//     c. 等待发现同步完成
	//   - 这样确保在发现就绪前，所有 APIService 都已注册
	s.GenericAPIServer.AddPostStartHookOrDie("apiservice-discovery-controller", func(context genericapiserver.PostStartHookContext) error {
		// Discovery aggregation depends on the apiservice registration controller
		// having the full list of APIServices already synced
		select {
		case <-context.Done():
			return nil
		// Context cancelled, should abort/clean goroutines
		case <-apiServiceRegistrationControllerInitiated:
		}

		// Run discovery manager's worker to watch for new/removed/updated
		// APIServices to the discovery document can be updated at runtime
		// When discovery is ready, all APIServices will be present, with APIServices
		// that have not successfully synced discovery to be present but marked as Stale.
		discoverySyncedCh := make(chan struct{})
		go s.discoveryAggregationController.Run(context.Done(), discoverySyncedCh)

		select {
		case <-context.Done():
			return nil
		// Context cancelled, should abort/clean goroutines
		case <-discoverySyncedCh:
			// API services successfully sync
		}
		return nil
	})

	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.StorageVersionAPI) &&
		utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIServerIdentity) {
		// Spawn a goroutine in aggregator apiserver to update storage version for
		// all built-in resources
		s.GenericAPIServer.AddPostStartHookOrDie(StorageVersionPostStartHookName, func(hookContext genericapiserver.PostStartHookContext) error {
			// Wait for apiserver-identity to exist first before updating storage
			// versions, to avoid storage version GC accidentally garbage-collecting
			// storage versions.
			kubeClient, err := kubernetes.NewForConfig(hookContext.LoopbackClientConfig)
			if err != nil {
				return err
			}
			if err := wait.PollImmediateUntil(100*time.Millisecond, func() (bool, error) {
				_, err := kubeClient.CoordinationV1().Leases(metav1.NamespaceSystem).Get(
					context.TODO(), s.GenericAPIServer.APIServerID, metav1.GetOptions{})
				if apierrors.IsNotFound(err) {
					return false, nil
				}
				if err != nil {
					return false, err
				}
				return true, nil
			}, hookContext.Done()); err != nil {
				return fmt.Errorf("failed to wait for apiserver-identity lease %s to be created: %v",
					s.GenericAPIServer.APIServerID, err)
			}
			// Technically an apiserver only needs to update storage version once during bootstrap.
			// Reconcile StorageVersion objects every 10 minutes will help in the case that the
			// StorageVersion objects get accidentally modified/deleted by a different agent. In that
			// case, the reconciliation ensures future storage migration still works. If nothing gets
			// changed, the reconciliation update is a noop and gets short-circuited by the apiserver,
			// therefore won't change the resource version and trigger storage migration.
			go wait.PollImmediateUntil(10*time.Minute, func() (bool, error) {
				// All apiservers (aggregator-apiserver, kube-apiserver, apiextensions-apiserver)
				// share the same generic apiserver config. The same StorageVersion manager is used
				// to register all built-in resources when the generic apiservers install APIs.
				s.GenericAPIServer.StorageVersionManager.UpdateStorageVersions(hookContext.LoopbackClientConfig, s.GenericAPIServer.APIServerID)
				return false, nil
			}, hookContext.Done())
			// Once the storage version updater finishes the first round of update,
			// the PostStartHook will return to unblock /healthz. The handler chain
			// won't block write requests anymore. Check every second since it's not
			// expensive.
			wait.PollImmediateUntil(1*time.Second, func() (bool, error) {
				return s.GenericAPIServer.StorageVersionManager.Completed(), nil
			}, hookContext.Done())
			return nil
		})
	}

	return s, nil
}

```

# k8s apiserver PrepareRun()


```go

//  1. 钩子优先级：在通用 PrepareRun 之前添加钩子，确保执行顺序
//   2. 延迟初始化：OpenAPI 聚合器的设置需要等待委托服务器准备完成
//   3. 双版本支持：同时支持 OpenAPI v2 和 v3
//   4. 异步运行：控制器在 goroutine 中运行，不阻塞启动


// PrepareRun prepares the aggregator to run, by setting up the OpenAPI spec &
// aggregated discovery document and calling the generic PrepareRun.
func (s *APIAggregator) PrepareRun() (preparedAPIAggregator, error) {
	// add post start hook before generic PrepareRun in order to be before /healthz installation
	if s.openAPIConfig != nil {
		s.GenericAPIServer.AddPostStartHookOrDie("apiservice-openapi-controller", func(context genericapiserver.PostStartHookContext) error {
			go s.openAPIAggregationController.Run(context.Done())
			return nil
		})
	}

	if s.openAPIV3Config != nil {
		s.GenericAPIServer.AddPostStartHookOrDie("apiservice-openapiv3-controller", func(context genericapiserver.PostStartHookContext) error {
			go s.openAPIV3AggregationController.Run(context.Done())
			return nil
		})
	}

	prepared := s.GenericAPIServer.PrepareRun()

	// delay OpenAPI setup until the delegate had a chance to setup their OpenAPI handlers
	if s.openAPIConfig != nil {
		specDownloader := openapiaggregator.NewDownloader()
		openAPIAggregator, err := openapiaggregator.BuildAndRegisterAggregator(
			&specDownloader,
			s.GenericAPIServer.NextDelegate(),
			s.GenericAPIServer.Handler.GoRestfulContainer.RegisteredWebServices(),
			s.openAPIConfig,
			s.GenericAPIServer.Handler.NonGoRestfulMux)
		if err != nil {
			return preparedAPIAggregator{}, err
		}
		s.openAPIAggregationController = openapicontroller.NewAggregationController(&specDownloader, openAPIAggregator)
	}

	if s.openAPIV3Config != nil {
		specDownloaderV3 := openapiv3aggregator.NewDownloader()
		openAPIV3Aggregator, err := openapiv3aggregator.BuildAndRegisterAggregator(
			specDownloaderV3,
			s.GenericAPIServer.NextDelegate(),
			s.GenericAPIServer.Handler.GoRestfulContainer,
			s.openAPIV3Config,
			s.GenericAPIServer.Handler.NonGoRestfulMux)
		if err != nil {
			return preparedAPIAggregator{}, err
		}
		s.openAPIV3AggregationController = openapiv3controller.NewAggregationController(openAPIV3Aggregator)
	}

	return preparedAPIAggregator{APIAggregator: s, runnable: prepared}, nil
}

```

# AddAPIService()
```go

// AddAPIService adds an API service.  It is not thread-safe, so only call it on one thread at a time please.
// It's a slow moving API, so its ok to run the controller on a single thread
// 动态添加和更新API服务
// 将自定义资源服务（CRD 服务或扩展 API 服务）注册到聚合 API 服务器中，使其可以通过统一的 API 端点访问。

// 工作流程示例

// 添加一个 custom.example.com/v1 API 服务：

// 1. 检查是否已存在 → 不存在
// 2. 构建路径 /apis/custom.example.com/v1
// 3. 创建 proxyHandler 并配置
// 4. 注册路由：
//   - /apis/custom.example.com/v1 → 精确匹配
//   - /apis/custom.example.com/v1/* → 前缀匹配
// 5. 首次注册该群组时，创建群组发现端点 /apis/custom.example.com
// 这样客户端就可以通过 kube-apiserver 访问自定义 API 服务，无需直接连接后端服务。

func (s *APIAggregator) AddAPIService(apiService *v1.APIService) error {
	// if the proxyHandler already exists, it needs to be updated. The aggregation bits do not
	// since they are wired against listers because they require multiple resources to respond
	if proxyHandler, exists := s.proxyHandlers[apiService.Name]; exists {
		proxyHandler.updateAPIService(apiService)
		if s.openAPIAggregationController != nil {
			s.openAPIAggregationController.UpdateAPIService(proxyHandler, apiService)
		}
		if s.openAPIV3AggregationController != nil {
			s.openAPIV3AggregationController.UpdateAPIService(proxyHandler, apiService)
		}
		// Forward calls to discovery manager to update discovery document
		if s.discoveryAggregationController != nil {
			handlerCopy := *proxyHandler
			handlerCopy.setServiceAvailable()
			s.discoveryAggregationController.AddAPIService(apiService, &handlerCopy)
		}
		return nil
	}

	// 2 构建代理路径
	// - 标准路径：/apis/{group}/{version}
	// - 特殊处理：legacy API（core v1）使用 /api
	proxyPath := "/apis/" + apiService.Spec.Group + "/" + apiService.Spec.Version
	// v1. is a special case for the legacy API.  It proxies to a wider set of endpoints.
	if apiService.Name == legacyAPIServiceName {
		proxyPath = "/api"
	}

	// register the proxy handler
	// - 创建代理处理器，负责：
	// - 转发请求到后端服务
	// - 处理认证和授权
	// - 管理服务可用性
	proxyHandler := &proxyHandler{
		localDelegate:              s.delegateHandler,
		proxyCurrentCertKeyContent: s.proxyCurrentCertKeyContent,
		proxyTransportDial:         s.proxyTransportDial,
		serviceResolver:            s.serviceResolver,
		rejectForwardingRedirects:  s.rejectForwardingRedirects,
		tracerProvider:             s.tracerProvider,
	}
	proxyHandler.updateAPIService(apiService)
	if s.openAPIAggregationController != nil {
		s.openAPIAggregationController.AddAPIService(proxyHandler, apiService)
	}
	if s.openAPIV3AggregationController != nil {
		s.openAPIV3AggregationController.AddAPIService(proxyHandler, apiService)
	}
	if s.discoveryAggregationController != nil {
		s.discoveryAggregationController.AddAPIService(apiService, proxyHandler)
	}
	// 4 注册到HTTP路由
	// - 精确匹配：/apis/group/version
	// - 前缀匹配：/apis/group/version/*
	s.proxyHandlers[apiService.Name] = proxyHandler
	s.GenericAPIServer.Handler.NonGoRestfulMux.Handle(proxyPath, proxyHandler)
	s.GenericAPIServer.Handler.NonGoRestfulMux.UnlistedHandlePrefix(proxyPath+"/", proxyHandler)

	// if we're dealing with the legacy group, we're done here
	if apiService.Name == legacyAPIServiceName {
		return nil
	}

	// if we've already registered the path with the handler, we don't want to do it again.
	versions, exist := s.handledGroupVersions[apiService.Spec.Group]
	if exist {
		versions.Insert(apiService.Spec.Version)
		return nil
	}

	// it's time to register the group aggregation endpoint
	// 5. 注册群组级别发现端点
	// - 处理 /apis/{group} 请求
	// - 返回该群组下所有可用版本的列表
	// - 避免重复注册同一群组
	groupPath := "/apis/" + apiService.Spec.Group
	groupDiscoveryHandler := &apiGroupHandler{
		codecs:    aggregatorscheme.Codecs,
		groupName: apiService.Spec.Group,
		lister:    s.lister,
		delegate:  s.delegateHandler,
	}
	// aggregation is protected

	s.GenericAPIServer.Handler.NonGoRestfulMux.Handle(groupPath, groupDiscoveryHandler)
	s.GenericAPIServer.Handler.NonGoRestfulMux.UnlistedHandle(groupPath+"/", groupDiscoveryHandler)
	s.handledGroupVersions[apiService.Spec.Group] = sets.New[string](apiService.Spec.Version)
	return nil
}
``` 
