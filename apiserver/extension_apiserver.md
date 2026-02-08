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

### 创建 apiExtensions config

```go
	// 3 创建API Extensions配置 用于配置CRD（自定义资源定义）系统
	apiExtensions, err := controlplaneapiserver.CreateAPIExtensionsConfig(*kubeAPIs.ControlPlane.Generic, kubeAPIs.ControlPlane.VersionedInformers, pluginInitializer, opts.CompletedOptions, opts.MasterCount,
		serviceResolver, webhook.NewDefaultAuthenticationInfoResolverWrapper(kubeAPIs.ControlPlane.ProxyTransport, kubeAPIs.ControlPlane.Generic.EgressSelector, kubeAPIs.ControlPlane.Generic.LoopbackClientConfig, kubeAPIs.ControlPlane.Generic.TracerProvider))
	if err != nil {
		return nil, err
	}
	c.ApiExtensions = apiExtensions

```

CreateAPIExtensionsConfig  创建API Extensions Server的config

pkg/controlplane/apiserver/apiextensions.go

```go
// 创建API Extensions(CRD相关)配置；
// API Extensions Server专门用例处理CRD
// 1. 配置隔离: API Extensions Server 使用独立的 etcd 存储和配置
// 2. 版本兼容: 同时支持 v1beta1 和 v1 的 CRD 对象
// 3. 避免冲突: 清空钩子防止多个服务器间冲突
func CreateAPIExtensionsConfig(
	kubeAPIServerConfig server.Config,
	kubeInformers informers.SharedInformerFactory,
	pluginInitializers []admission.PluginInitializer,
	commandOptions options.CompletedOptions,
	masterCount int,
	serviceResolver webhook.ServiceResolver,
	authResolverWrapper webhook.AuthenticationInfoResolverWrapper,
) (*apiextensionsapiserver.Config, error) {
	// make a shallow copy to let us twiddle a few things
	// most of the config actually remains the same.  We only need to mess with a couple items related to the particulars of the apiextensions
	genericConfig := kubeAPIServerConfig
	genericConfig.PostStartHooks = map[string]server.PostStartHookConfigEntry{} // 清空PostStartHooks，避免重复注册钩子
	genericConfig.RESTOptionsGetter = nil                                       // 重置RESTOptionsGetter

	// copy the etcd options so we don't mutate originals.
	// we assume that the etcd options have been completed already.  avoid messing with anything outside
	// of changes to StorageConfig as that may lead to unexpected behavior when the options are applied.
	etcdOptions := *commandOptions.Etcd
	// this is where the true decodable levels come from.
	etcdOptions.StorageConfig.Codec = apiextensionsapiserver.Codecs.LegacyCodec(v1beta1.SchemeGroupVersion, v1.SchemeGroupVersion)
	// prefer the more compact serialization (v1beta1) for storage until https://issue.k8s.io/82292 is resolved for objects whose v1 serialization is too big but whose v1beta1 serialization can be stored
	etcdOptions.StorageConfig.EncodeVersioner = runtime.NewMultiGroupVersioner(v1beta1.SchemeGroupVersion, schema.GroupKind{Group: v1beta1.GroupName})
	etcdOptions.SkipHealthEndpoints = true // avoid double wiring of health checks
	if err := etcdOptions.ApplyTo(&genericConfig); err != nil {
		return nil, err
	}

	// override MergedResourceConfig with apiextensions defaults and registry
	if err := commandOptions.APIEnablement.ApplyTo(
		&genericConfig,
		apiextensionsapiserver.DefaultAPIResourceConfigSource(),
		apiextensionsapiserver.Scheme); err != nil {
		return nil, err
	}
	apiextensionsConfig := &apiextensionsapiserver.Config{
		GenericConfig: &server.RecommendedConfig{
			Config:                genericConfig,
			SharedInformerFactory: kubeInformers,
		},
		ExtraConfig: apiextensionsapiserver.ExtraConfig{ // API Extensions特点配置（CRD存储、认证解析、服务解析等）
			CRDRESTOptionsGetter: apiextensionsoptions.NewCRDRESTOptionsGetter(etcdOptions, genericConfig.ResourceTransformers, genericConfig.StorageObjectCountTracker),
			MasterCount:          masterCount,
			AuthResolverWrapper:  authResolverWrapper,
			ServiceResolver:      serviceResolver,
		},
	}

	// we need to clear the poststarthooks so we don't add them multiple times to all the servers (that fails)
	apiextensionsConfig.GenericConfig.PostStartHooks = map[string]server.PostStartHookConfigEntry{}

	return apiextensionsConfig, nil
}

```

### kubeapis.complete()

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

# 创建 Extension Server 实例

apiExtensionsServer, err := config.ApiExtensions.New(genericapiserver.NewEmptyDelegateWithCustomHandler(notFoundHandler))

```go

// 渐进式启动：   分阶段启动Informers -> 控制器 -> 等待同步
// 动态发现 CRD： Handler和Discovery Controller支持动态添加/删除API
// 多控制器协作： 不同控制器负责CRD生命周期的不同方面
// OpenAPI集成： 自动为CRD生成OpenAPI文档
// New returns a new instance of CustomResourceDefinitions from the given config.
func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*CustomResourceDefinitions, error) {
	// 创建通用的Server genericServer
	genericServer, err := c.GenericConfig.New("apiextensions-apiserver", delegationTarget)
	if err != nil {
		return nil, err
	}

	// hasCRDInformerSyncedSignal is closed when the CRD informer this server uses has been fully synchronized.
	// It ensures that requests to potential custom resource endpoints while the server hasn't installed all known HTTP paths get a 503 error instead of a 404
	hasCRDInformerSyncedSignal := make(chan struct{})
	if err := genericServer.RegisterMuxAndDiscoveryCompleteSignal("CRDInformerHasNotSynced", hasCRDInformerSyncedSignal); err != nil {
		return nil, err
	}

	s := &CustomResourceDefinitions{
		GenericAPIServer: genericServer,
	}

	apiResourceConfig := c.GenericConfig.MergedResourceConfig
	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(apiextensions.GroupName, Scheme, metav1.ParameterCodec, Codecs)

	// 创建CRD Storage并注册API
	storage := map[string]rest.Storage{}
	// customresourcedefinitions
	if resource := "customresourcedefinitions"; apiResourceConfig.ResourceEnabled(v1.SchemeGroupVersion.WithResource(resource)) {
		customResourceDefinitionStorage, err := customresourcedefinition.NewREST(Scheme, c.GenericConfig.RESTOptionsGetter)
		if err != nil {
			return nil, err
		}
		storage[resource] = customResourceDefinitionStorage
		storage[resource+"/status"] = customresourcedefinition.NewStatusREST(Scheme, customResourceDefinitionStorage)
	}
	if len(storage) > 0 {
		apiGroupInfo.VersionedResourcesStorageMap[v1.SchemeGroupVersion.Version] = storage
	}

	// 安装 /apis/apiextensions.k8s.io/v1/customresourcedefinitions 端点
	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

	crdClient, err := clientset.NewForConfig(s.GenericAPIServer.LoopbackClientConfig)
	if err != nil {
		// it's really bad that this is leaking here, but until we can fix the test (which I'm pretty sure isn't even testing what it wants to test),
		// we need to be able to move forward
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}
	// 4 创建Informer工厂
	// 监听CRD变化的Informer工厂（5分钟重新同步周期）
	s.Informers = externalinformers.NewSharedInformerFactory(crdClient, 5*time.Minute)

	delegateHandler := delegationTarget.UnprotectedHandler()
	if delegateHandler == nil {
		delegateHandler = http.NotFoundHandler()
	}

	// 5 创建发现处理器
	// 动态处理 /apis 和 /apis/{group}/{version} 的发现请求
	// 因为 CRD 可以动态添加/删除 API
	versionDiscoveryHandler := &versionDiscoveryHandler{
		discovery: map[schema.GroupVersion]*discovery.APIVersionHandler{},
		delegate:  delegateHandler,
	}
	groupDiscoveryHandler := &groupDiscoveryHandler{
		discovery: map[string]*discovery.APIGroupHandler{},
		delegate:  delegateHandler,
	}
	// 控制器 管理CRD的建立状态（等待相关资源就绪）
	establishingController := establish.NewEstablishingController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())

	// 6 创建CRD Handler(核心)
	// 创建处理所有CRD请求的handler
	// 注册到 /apis和/apis/路径
	crdHandler, err := NewCustomResourceDefinitionHandler(
		versionDiscoveryHandler,
		groupDiscoveryHandler,
		s.Informers.Apiextensions().V1().CustomResourceDefinitions(),
		delegateHandler,
		c.ExtraConfig.CRDRESTOptionsGetter,
		c.GenericConfig.AdmissionControl,
		establishingController,
		c.ExtraConfig.ServiceResolver,
		c.ExtraConfig.AuthResolverWrapper,
		c.ExtraConfig.MasterCount,
		s.GenericAPIServer.Authorizer,
		c.GenericConfig.RequestTimeout,
		time.Duration(c.GenericConfig.MinRequestTimeout)*time.Second,
		apiGroupInfo.StaticOpenAPISpec,
		c.GenericConfig.MaxRequestBodyBytes,
	)
	if err != nil {
		return nil, err
	}
	s.GenericAPIServer.Handler.NonGoRestfulMux.Handle("/apis", crdHandler)
	s.GenericAPIServer.Handler.NonGoRestfulMux.HandlePrefix("/apis/", crdHandler)
	s.GenericAPIServer.RegisterDestroyFunc(crdHandler.destroy)

	aggregatedDiscoveryManager := genericServer.AggregatedDiscoveryGroupManager
	if aggregatedDiscoveryManager != nil {
		aggregatedDiscoveryManager = aggregatedDiscoveryManager.WithSource(aggregated.CRDSource)
	}
	// 控制器 更新API发现信息（当CRD变化时）
	discoveryController := NewDiscoveryController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), versionDiscoveryHandler, groupDiscoveryHandler, aggregatedDiscoveryManager)
	// 控制器 检查CRD命名规范
	namingController := status.NewNamingConditionController(klog.TODO() /* for contextual logging */, s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())
	// 控制器 检查Schema结构
	nonStructuralSchemaController := nonstructuralschema.NewConditionController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())
	// 控制器 检查API审批策略
	apiApprovalController := apiapproval.NewKubernetesAPIApprovalPolicyConformantConditionController(s.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdClient.ApiextensionsV1())
	// 控制器 处理CRD删除时的清理
	finalizingController := finalizer.NewCRDFinalizer(
		s.Informers.Apiextensions().V1().CustomResourceDefinitions(),
		crdClient.ApiextensionsV1(),
		crdHandler,
	)

	// 启动Informer
	s.GenericAPIServer.AddPostStartHookOrDie("start-apiextensions-informers", func(hookContext genericapiserver.PostStartHookContext) error {
		s.Informers.Start(hookContext.Done())
		return nil
	})

	// 启动控制器
	s.GenericAPIServer.AddPostStartHookOrDie("start-apiextensions-controllers", func(hookContext genericapiserver.PostStartHookContext) error {
		// OpenAPIVersionedService and StaticOpenAPISpec are populated in generic apiserver PrepareRun().
		// Together they serve the /openapi/v2 endpoint on a generic apiserver. A generic apiserver may
		// choose to not enable OpenAPI by having null openAPIConfig, and thus OpenAPIVersionedService
		// and StaticOpenAPISpec are both null. In that case we don't run the CRD OpenAPI controller.
		if s.GenericAPIServer.StaticOpenAPISpec != nil {
			if s.GenericAPIServer.OpenAPIVersionedService != nil {
				openapiController := openapicontroller.NewController(s.Informers.Apiextensions().V1().CustomResourceDefinitions())
				go openapiController.Run(s.GenericAPIServer.StaticOpenAPISpec, s.GenericAPIServer.OpenAPIVersionedService, hookContext.Done())
			}

			if s.GenericAPIServer.OpenAPIV3VersionedService != nil {
				openapiv3Controller := openapiv3controller.NewController(s.Informers.Apiextensions().V1().CustomResourceDefinitions())
				go openapiv3Controller.Run(s.GenericAPIServer.OpenAPIV3VersionedService, hookContext.Done())
			}
		}

		go namingController.Run(hookContext.Done())
		go establishingController.Run(hookContext.Done())
		go nonStructuralSchemaController.Run(5, hookContext.Done())
		go apiApprovalController.Run(5, hookContext.Done())
		go finalizingController.Run(5, hookContext.Done())

		discoverySyncedCh := make(chan struct{})
		go discoveryController.Run(hookContext.Done(), discoverySyncedCh)
		select {
		case <-hookContext.Done():
		case <-discoverySyncedCh:
		}

		return nil
	})
	// we don't want to report healthy until we can handle all CRDs that have already been registered.  Waiting for the informer
	// to sync makes sure that the lister will be valid before we begin.  There may still be races for CRDs added after startup,
	// but we won't go healthy until we can handle the ones already present.
	s.GenericAPIServer.AddPostStartHookOrDie("crd-informer-synced", func(ctx genericapiserver.PostStartHookContext) error {
		return wait.PollUntilContextCancel(ctx.Context, 100*time.Millisecond, true, func(ctx context.Context) (bool, error) {
			if s.Informers.Apiextensions().V1().CustomResourceDefinitions().Informer().HasSynced() {
				close(hasCRDInformerSyncedSignal)
				return true, nil
			}
			return false, nil
		})
	})

	return s, nil
}

```

# ServerHttp 处理CRD请求

```go

// ServeHTTP是CRD Handler的核心处理方法，拦截/apis路径下的所有请求，判断是否为CRD请求，并动态路由到对应的处理器
func (r *crdHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	// 提取请求信息
	requestInfo, ok := apirequest.RequestInfoFrom(ctx)
	if !ok {
		responsewriters.ErrorNegotiated(
			apierrors.NewInternalError(fmt.Errorf("no RequestInfo found in the context")),
			Codecs, schema.GroupVersion{}, w, req,
		)
		return
	}
	if !requestInfo.IsResourceRequest {
		pathParts := splitPath(requestInfo.Path)
		// only match /apis/<group>/<version>
		// only registered under /apis
		if len(pathParts) == 3 {
			r.versionDiscoveryHandler.ServeHTTP(w, req)
			return
		}
		// only match /apis/<group>
		if len(pathParts) == 2 {
			r.groupDiscoveryHandler.ServeHTTP(w, req)
			return
		}

		r.delegate.ServeHTTP(w, req)
		return
	}

	crdName := requestInfo.Resource + "." + requestInfo.APIGroup
	// 查找CRD定义
	// 拼接 CRD 名称：<resource>.<group>（如 podmetrics.custom.metrics.k8s.io）
	crd, err := r.crdLister.Get(crdName)
	if apierrors.IsNotFound(err) {
		r.delegate.ServeHTTP(w, req)
		return
	}
	if err != nil {
		utilruntime.HandleError(err)
		responsewriters.ErrorNegotiated(
			apierrors.NewInternalError(fmt.Errorf("error resolving resource")),
			Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req,
		)
		return
	}

	// if the scope in the CRD and the scope in request differ (with exception of the verbs in possiblyAcrossAllNamespacesVerbs
	// for namespaced resources), pass request to the delegate, which is supposed to lead to a 404.
	// 	检查 CRD 作用域与请求是否匹配：
	//   - 集群范围 CRD + 有命名空间 → 不匹配，委托返回 404
	//   - 命名范围 CRD + 无命名空间 + 非跨命名空间操作 → 不匹配，委托返回 404
	namespacedCRD, namespacedReq := crd.Spec.Scope == apiextensionsv1.NamespaceScoped, len(requestInfo.Namespace) > 0
	if !namespacedCRD && namespacedReq {
		r.delegate.ServeHTTP(w, req)
		return
	}
	if namespacedCRD && !namespacedReq && !possiblyAcrossAllNamespacesVerbs.Has(requestInfo.Verb) {
		r.delegate.ServeHTTP(w, req)
		return
	}

	if !apiextensionshelpers.HasServedCRDVersion(crd, requestInfo.APIVersion) {
		r.delegate.ServeHTTP(w, req)
		return
	}

	// There is a small chance that a CRD is being served because NamesAccepted condition is true,
	// but it becomes "unserved" because another names update leads to a conflict
	// and EstablishingController wasn't fast enough to put the CRD into the Established condition.
	// We accept this as the problem is small and self-healing.
	if !apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.NamesAccepted) &&
		!apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.Established) {
		r.delegate.ServeHTTP(w, req)
		return
	}

	terminating := apiextensionshelpers.IsCRDConditionTrue(crd, apiextensionsv1.Terminating)

	crdInfo, err := r.getOrCreateServingInfoFor(crd.UID, crd.Name)
	if apierrors.IsNotFound(err) {
		r.delegate.ServeHTTP(w, req)
		return
	}
	if err != nil {
		utilruntime.HandleError(err)
		responsewriters.ErrorNegotiated(
			apierrors.NewInternalError(fmt.Errorf("error resolving resource")),
			Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req,
		)
		return
	}
	if !hasServedCRDVersion(crdInfo.spec, requestInfo.APIVersion) {
		r.delegate.ServeHTTP(w, req)
		return
	}

	deprecated := crdInfo.deprecated[requestInfo.APIVersion]
	for _, w := range crdInfo.warnings[requestInfo.APIVersion] {
		warning.AddWarning(req.Context(), "", w)
	}

	verb := strings.ToUpper(requestInfo.Verb)
	resource := requestInfo.Resource
	subresource := requestInfo.Subresource
	scope := metrics.CleanScope(requestInfo)
	supportedTypes := []string{
		string(types.JSONPatchType),
		string(types.MergePatchType),
		string(types.ApplyYAMLPatchType),
	}
	if utilfeature.DefaultFeatureGate.Enabled(features.CBORServingAndStorage) {
		supportedTypes = append(supportedTypes, string(types.ApplyCBORPatchType))
	}

	var handlerFunc http.HandlerFunc
	subresources, err := apiextensionshelpers.GetSubresourcesForVersion(crd, requestInfo.APIVersion)
	if err != nil {
		utilruntime.HandleError(err)
		responsewriters.ErrorNegotiated(
			apierrors.NewInternalError(fmt.Errorf("could not properly serve the subresource")),
			Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req,
		)
		return
	}

	// 路由到具体处理器
// 	根据子资源类型路由：
//   - status → serveStatus（处理状态子资源）
//   - scale → serveScale（处理扩缩容子资源）
//   - 无子资源 → serveResource（处理主资源）
  - 其他 → 返回 404
	switch {
	case subresource == "status" && subresources != nil && subresources.Status != nil:
		handlerFunc = r.serveStatus(w, req, requestInfo, crdInfo, terminating, supportedTypes)
	case subresource == "scale" && subresources != nil && subresources.Scale != nil:
		handlerFunc = r.serveScale(w, req, requestInfo, crdInfo, terminating, supportedTypes)
	case len(subresource) == 0:
		handlerFunc = r.serveResource(w, req, requestInfo, crdInfo, crd, terminating, supportedTypes)
	default:
		responsewriters.ErrorNegotiated(
			apierrors.NewNotFound(schema.GroupResource{Group: requestInfo.APIGroup, Resource: requestInfo.Resource}, requestInfo.Name),
			Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req,
		)
	}

	if handlerFunc != nil {
		handlerFunc = metrics.InstrumentHandlerFunc(verb, requestInfo.APIGroup, requestInfo.APIVersion, resource, subresource, scope, metrics.APIServerComponent, deprecated, "", handlerFunc)
		handler := genericfilters.WithWaitGroup(handlerFunc, longRunningFilter, crdInfo.waitGroup)
		handler.ServeHTTP(w, req)
		return
	}
}
```

## ServeResource

```go
// 根据请求的HTTP类型（GET、POST、PUT、DELETE、PATCH）返回对应的处理器函数，处理对CRD实例的具体操作

// 操作对比表
// ┌──────────────────┬───────────┬─────────────────────────────────────┬────────────────────────────────┬──────────────┐
// │       动词       │ HTTP 方法 │              路径示例               │             处理器             │ 是否准入控制 │
// ├──────────────────┼───────────┼─────────────────────────────────────┼────────────────────────────────┼──────────────┤
// │ get              │ GET       │ /apis/group/v1/resources/name       │ GetResource                    │ 否           │
// ├──────────────────┼───────────┼─────────────────────────────────────┼────────────────────────────────┼──────────────┤
// │ list             │ GET       │ /apis/group/v1/resources            │ ListResource                   │ 否           │
// ├──────────────────┼───────────┼─────────────────────────────────────┼────────────────────────────────┼──────────────┤
// │ watch            │ GET       │ /apis/group/v1/resources?watch=true │ ListResource (forceWatch=true) │ 否           │
// ├──────────────────┼───────────┼─────────────────────────────────────┼────────────────────────────────┼──────────────┤
// │ create           │ POST      │ /apis/group/v1/resources            │ CreateResource                 │ 是           │
// ├──────────────────┼───────────┼─────────────────────────────────────┼────────────────────────────────┼──────────────┤
// │ update           │ PUT       │ /apis/group/v1/resources/name       │ UpdateResource                 │ 是           │
// ├──────────────────┼───────────┼─────────────────────────────────────┼────────────────────────────────┼──────────────┤
// │ patch            │ PATCH     │ /apis/group/v1/resources/name       │ PatchResource                  │ 是           │
// ├──────────────────┼───────────┼─────────────────────────────────────┼────────────────────────────────┼──────────────┤
// │ delete           │ DELETE    │ /apis/group/v1/resources/name       │ DeleteResource                 │ 是           │
// ├──────────────────┼───────────┼─────────────────────────────────────┼────────────────────────────────┼──────────────┤
// │ deletecollection │ DELETE    │ /apis/group/v1/resources            │ DeleteCollection               │ 是

func (r *crdHandler) serveResource(w http.ResponseWriter, req *http.Request, requestInfo *apirequest.RequestInfo, crdInfo *crdInfo, crd *apiextensionsv1.CustomResourceDefinition, terminating bool, supportedTypes []string) http.HandlerFunc {
	requestScope := crdInfo.requestScopes[requestInfo.APIVersion]
	storage := crdInfo.storages[requestInfo.APIVersion].CustomResource

	switch requestInfo.Verb {
	case "get":
		return handlers.GetResource(storage, requestScope)
	case "list":
		forceWatch := false
		return handlers.ListResource(storage, storage, requestScope, forceWatch, r.minRequestTimeout)
	case "watch":
		forceWatch := true
		return handlers.ListResource(storage, storage, requestScope, forceWatch, r.minRequestTimeout)
	case "create":
		// we want to track recently created CRDs so that in HA environments we don't have server A allow a create and server B
		// not have observed the established, so a followup get,update,delete results in a 404. We've observed about 800ms
		// delay in some CI environments.  Two seconds looks long enough and reasonably short for hot retriers.
		justCreated := time.Since(apiextensionshelpers.FindCRDCondition(crd, apiextensionsv1.Established).LastTransitionTime.Time) < 2*time.Second
		if justCreated {
			time.Sleep(2 * time.Second)
		}

		a := r.admission
		if terminating {
			a = &forbidCreateAdmission{delegate: a}
		}
		return handlers.CreateResource(storage, requestScope, a)
	case "update":
		return handlers.UpdateResource(storage, requestScope, r.admission)
	case "patch":
		a := r.admission
		if terminating {
			a = &forbidCreateAdmission{delegate: a}
		}
		return handlers.PatchResource(storage, requestScope, a, supportedTypes)
	case "delete":
		allowsOptions := true
		return handlers.DeleteResource(storage, allowsOptions, requestScope, r.admission)
	case "deletecollection":
		checkBody := true
		return handlers.DeleteCollection(storage, checkBody, requestScope, r.admission)
	default:
		responsewriters.ErrorNegotiated(
			apierrors.NewMethodNotSupported(schema.GroupResource{Group: requestInfo.APIGroup, Resource: requestInfo.Resource}, requestInfo.Verb),
			Codecs, schema.GroupVersion{Group: requestInfo.APIGroup, Version: requestInfo.APIVersion}, w, req,
		)
		return nil
	}
}
```

### GetResource

```go
// GetResource returns a function that handles retrieving a single resource from a rest.Storage object.

// GetResource (创建处理器)
//       ↓
//   getResourceHandler (通用处理逻辑)
//       ↓
//   getterFunc (存储操作)
//       ↓
//   r.Get() (实际数据获取)

//   请求流程

// HTTP GET /api/v1/pods/my-pod?pretty=true
//
//	↓
//
// GetResource 创建 Handler
//
//	↓
//
// getResourceHandler 处理通用逻辑
//
//	├─ 解析名称空间和名称
//	├─ 协商响应类型
//	└─ 调用 getterFunc
//	    ↓
//	    getterFunc 执行
//	    ├─ 记录指标
//	    ├─ 检查 export 参数（已废弃）
//	    ├─ 解析 GetOptions
//	    └─ 调用 r.Get(ctx, "my-pod", options)
//	        ↓
//	        Storage 从 etcd 读取
//	        ↓
//	        返回资源对象
//	↓
//
// 序列化并响应

// 这里的rest.Getter指的是 storage
func GetResource(r rest.Getter, scope *RequestScope) http.HandlerFunc {
	return getResourceHandler(scope,
		func(ctx context.Context, name string, req *http.Request) (runtime.Object, error) {
			// check for export
			metrics.RequestAcceptCounter.WithContext(ctx).WithLabelValues(req.UserAgent(), scope.Resource.Resource, "GET", req.Header.Get("Accept")).Inc()
			options := metav1.GetOptions{}
			if values := req.URL.Query(); len(values) > 0 {
				if len(values["export"]) > 0 {
					exportBool := true
					exportStrings := values["export"]
					err := runtime.Convert_Slice_string_To_bool(&exportStrings, &exportBool, nil)
					if err != nil {
						return nil, errors.NewBadRequest(fmt.Sprintf("the export parameter cannot be parsed: %v", err))
					}
					if exportBool {
						return nil, errors.NewBadRequest("the export parameter, deprecated since v1.14, is no longer supported")
					}
				}
				if err := metainternalversionscheme.ParameterCodec.DecodeParameters(values, scope.MetaGroupVersion, &options); err != nil {
					err = errors.NewBadRequest(err.Error())
					return nil, err
				}
			}
			tracing.SpanFromContext(ctx).AddEvent("About to Get from storage")
			return r.Get(ctx, name, &options)
		})
}


```

#### getResourceHandler

```go
// 请求流程图

// HTTP GET Request
// 	↓
// 解析 namespace 和 name
// 	↓
// 协商响应类型 (Accept → JSON/YAML/Protobuf)
// 	↓
// 记录指标
// 	↓
// 调用 getter 函数
// 	├─ 从 Storage 读取
// 	└─ Storage 从 etcd 读取
// 	↓
// 序列化对象
// 	↓
// 应用转换器
// 	↓
// 返回 HTTP 200 + 响应体

func getResourceHandler(scope *RequestScope, getter getterFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		ctx, span := tracing.Start(ctx, "Get", traceFields(req)...)
		req = req.WithContext(ctx)
		defer span.End(500 * time.Millisecond)

		namespace, name, err := scope.Namer.Name(req)
		if err != nil {
			scope.err(err, w, req)
			return
		}
		ctx = request.WithNamespace(ctx, namespace)

		outputMediaType, _, err := negotiation.NegotiateOutputMediaType(req, scope.Serializer, scope)
		if err != nil {
			scope.err(err, w, req)
			return
		}

		metrics.RecordTransformerRequest(ctx, outputMediaType.Transformer, req.UserAgent(), scope.Resource.Resource, http.MethodGet)

		result, err := getter(ctx, name, req)
		if err != nil {
			scope.err(err, w, req)
			return
		}

		span.AddEvent("About to write a response")
		defer span.AddEvent("Writing http response done")
		transformResponseObject(ctx, scope, req, w, http.StatusOK, outputMediaType, result, nil)
	}
}
```
 这份总结好吗？
