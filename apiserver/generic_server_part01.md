# generic server的初始化

cmd/kube-apiserver/app/server.go

```go
func CreateServerChain(config CompletedConfig) (*aggregatorapiserver.APIAggregator, error) {
	notFoundHandler := notfoundhandler.New(config.KubeAPIs.ControlPlane.Generic.Serializer, genericapifilters.NoMuxAndDiscoveryIncompleteKey)
	apiExtensionsServer, err := config.ApiExtensions.New(genericapiserver.NewEmptyDelegateWithCustomHandler(notFoundHandler))
	if err != nil {
		return nil, err
	}
	crdAPIEnabled := config.ApiExtensions.GenericConfig.MergedResourceConfig.ResourceEnabled(apiextensionsv1.SchemeGroupVersion.WithResource("customresourcedefinitions"))
  
    // 创建master apiserver
	kubeAPIServer, err := config.KubeAPIs.New(apiExtensionsServer.GenericAPIServer)
	if err != nil {
		return nil, err
	}

	// aggregator comes last in the chain
	aggregatorServer, err := controlplaneapiserver.CreateAggregatorServer(config.Aggregator, kubeAPIServer.ControlPlane.GenericAPIServer, apiExtensionsServer.Informers.Apiextensions().V1().CustomResourceDefinitions(), crdAPIEnabled, apiVersionPriorities)
	if err != nil {
		// we don't need special handling for innerStopCh because the aggregator server doesn't create any go routines
		return nil, err
	}

	return aggregatorServer, nil
}
```


```golang
// 这里的delegationTarget 就是 apiExtensionsServer.GenericAPIServer  
func (c CompletedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*Instance, error) {
	if reflect.DeepEqual(c.Extra.KubeletClientConfig, kubeletclient.KubeletClientConfig{}) {
		return nil, fmt.Errorf("Master.New() called with empty config.KubeletClientConfig")
	}

    // 创建generic apiserver
	cp, err := c.ControlPlane.New(controlplaneapiserver.KubeAPIServer, delegationTarget)
	if err != nil {
		return nil, err
	}
        ......

	return s, nil

}
```

pkg/controlplane/apiserver/server.go

```golang

func (c completedConfig) New(name string, delegationTarget genericapiserver.DelegationTarget) (*Server, error) {
    // 创建generic server 重点！！！
	generic, err := c.Generic.New(name, delegationTarget)


	if err != nil {
		return nil, err
	}

	if c.EnableLogsSupport {
		routes.Logs{}.Install(generic.Handler.GoRestfulContainer)
	}

	md, err := serviceaccount.NewOpenIDMetadataProvider(
		c.ServiceAccountIssuerURL,
		c.ServiceAccountJWKSURI,
		c.Generic.ExternalAddress,
		c.ServiceAccountPublicKeysGetter,
	)
	if err != nil {
		// If there was an error, skip installing the endpoints and log the
		// error, but continue on. We don't return the error because the
		// metadata responses require additional, backwards incompatible
		// validation of command-line options.
		msg := fmt.Sprintf("Could not construct pre-rendered responses for"+
			" ServiceAccountIssuerDiscovery endpoints. Endpoints will not be"+
			" enabled. Error: %v", err)
		if c.ServiceAccountIssuerURL != "" {
			// The user likely expects this feature to be enabled if issuer URL is
			// set and the feature gate is enabled. In the future, if there is no
			// longer a feature gate and issuer URL is not set, the user may not
			// expect this feature to be enabled. We log the former case as an Error
			// and the latter case as an Info.
			klog.Error(msg)
		} else {
			klog.Info(msg)
		}
	} else {
		routes.NewOpenIDMetadataServer(md).Install(generic.Handler.GoRestfulContainer)
	}

	s := &Server{
		GenericAPIServer: generic,

		APIResourceConfigSource:   c.APIResourceConfigSource,
		RESTOptionsGetter:         c.Generic.RESTOptionsGetter,
		ClusterAuthenticationInfo: c.ClusterAuthenticationInfo,
		VersionedInformers:        c.VersionedInformers,
	}

    ......

	return s, nil
}
```

staging/src/k8s.io/apiserver/pkg/server/config.go

```golang
// 这里的delegationTarget 就是 apiExtensionsServer.GenericAPIServer  
func (c completedConfig) New(name string, delegationTarget DelegationTarget) (*GenericAPIServer, error) {
	if c.Serializer == nil {
		return nil, fmt.Errorf("Genericapiserver.New() called with config.Serializer == nil")
	}
	allowedMediaTypes := defaultAllowedMediaTypes
	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.CBORServingAndStorage) {
		allowedMediaTypes = append(allowedMediaTypes, runtime.ContentTypeCBOR)
	}
	for _, info := range c.Serializer.SupportedMediaTypes() {
		var ok bool
		for _, mt := range allowedMediaTypes {
			if info.MediaType == mt {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("refusing to create new apiserver %q with support for media type %q (allowed media types are: %s)", name, info.MediaType, strings.Join(allowedMediaTypes, ", "))
		}
	}
	if c.LoopbackClientConfig == nil {
		return nil, fmt.Errorf("Genericapiserver.New() called with config.LoopbackClientConfig == nil")
	}
	if c.EquivalentResourceRegistry == nil {
		return nil, fmt.Errorf("Genericapiserver.New() called with config.EquivalentResourceRegistry == nil")
	}

    // handlerChainBuilder 是一个变量，类型是 func(http.Handler) http.Handler
    // 接收一个参数：handler http.Handler（原始的 HTTP 处理器）
    // 返回一个：http.Handler（经过包装的处理链） 

	// BuildHandlerChainFunc会对handler层层装饰，添加上认证、鉴权、审计、限流等功能！
	handlerChainBuilder := func(handler http.Handler) http.Handler {
		return c.BuildHandlerChainFunc(handler, c.Config)
	}

	var debugSocket *routes.DebugSocket
	if c.DebugSocketPath != "" {
		debugSocket = routes.NewDebugSocket(c.DebugSocketPath)
	}

    // 创建 apiServerHandler，用来处理HTTP请求
	apiServerHandler := NewAPIServerHandler(name, c.Serializer, handlerChainBuilder, delegationTarget.UnprotectedHandler())

    // 初始化一个GenericAPIServer
	s := &GenericAPIServer{
		discoveryAddresses:             c.DiscoveryAddresses,
		LoopbackClientConfig:           c.LoopbackClientConfig,
		legacyAPIGroupPrefixes:         c.LegacyAPIGroupPrefixes,
		admissionControl:               c.AdmissionControl,
		Serializer:                     c.Serializer,
		AuditBackend:                   c.AuditBackend,
		Authorizer:                     c.Authorization.Authorizer,
		delegationTarget:               delegationTarget,
		EquivalentResourceRegistry:     c.EquivalentResourceRegistry,
		NonLongRunningRequestWaitGroup: c.NonLongRunningRequestWaitGroup,
		WatchRequestWaitGroup:          c.WatchRequestWaitGroup,
		Handler:                        apiServerHandler,  // 赋值给Handler
		UnprotectedDebugSocket:         debugSocket,

		listedPathProvider: apiServerHandler,

		minRequestTimeout:                   time.Duration(c.MinRequestTimeout) * time.Second,
		ShutdownTimeout:                     c.RequestTimeout,
		ShutdownDelayDuration:               c.ShutdownDelayDuration,
		ShutdownWatchTerminationGracePeriod: c.ShutdownWatchTerminationGracePeriod,
		SecureServingInfo:                   c.SecureServing,
		ExternalAddress:                     c.ExternalAddress,

		openAPIConfig:           c.OpenAPIConfig,
		openAPIV3Config:         c.OpenAPIV3Config,
		skipOpenAPIInstallation: c.SkipOpenAPIInstallation,

		postStartHooks:         map[string]postStartHookEntry{},   // Hooks
		preShutdownHooks:       map[string]preShutdownHookEntry{}, // Hooks
		disabledPostStartHooks: c.DisabledPostStartHooks,

		healthzRegistry:  healthCheckRegistry{path: "/healthz", checks: c.HealthzChecks},
		livezRegistry:    healthCheckRegistry{path: "/livez", checks: c.LivezChecks, clock: clock.RealClock{}},
		readyzRegistry:   healthCheckRegistry{path: "/readyz", checks: c.ReadyzChecks},
		livezGracePeriod: c.LivezGracePeriod,

		DiscoveryGroupManager: discovery.NewRootAPIsHandler(c.DiscoveryAddresses, c.Serializer),

		maxRequestBodyBytes: c.MaxRequestBodyBytes,

		lifecycleSignals:       c.lifecycleSignals,
		ShutdownSendRetryAfter: c.ShutdownSendRetryAfter,

		APIServerID:           c.APIServerID,
		StorageReadinessHook:  NewStorageReadinessHook(c.StorageInitializationTimeout),
		StorageVersionManager: c.StorageVersionManager,

		EffectiveVersion:                        c.EffectiveVersion,
		EmulationForwardCompatible:              c.EmulationForwardCompatible,
		RuntimeConfigEmulationForwardCompatible: c.RuntimeConfigEmulationForwardCompatible,
		FeatureGate:                             c.FeatureGate,

		muxAndDiscoveryCompleteSignals: map[string]<-chan struct{}{},
	}

	manager := c.AggregatedDiscoveryGroupManager
	if manager == nil {
		manager = discoveryendpoint.NewResourceManager("apis")
	}
	s.AggregatedDiscoveryGroupManager = manager
	s.AggregatedLegacyDiscoveryGroupManager = discoveryendpoint.NewResourceManager("api")
	for {
		if c.JSONPatchMaxCopyBytes <= 0 {
			break
		}
		existing := atomic.LoadInt64(&jsonpatch.AccumulatedCopySizeLimit)
		if existing > 0 && existing < c.JSONPatchMaxCopyBytes {
			break
		}
		if atomic.CompareAndSwapInt64(&jsonpatch.AccumulatedCopySizeLimit, existing, c.JSONPatchMaxCopyBytes) {
			break
		}
	}

	// first add poststarthooks from delegated targets
    // 添加 从delegated API Server的postStartHook
	for k, v := range delegationTarget.PostStartHooks() {
		s.postStartHooks[k] = v
	}

	for k, v := range delegationTarget.PreShutdownHooks() {
		s.preShutdownHooks[k] = v
	}
  
    // 添加各种hook
    ......

    // 安装API
	installAPI(name, s, c.Config)

	// use the UnprotectedHandler from the delegation target to ensure that we don't attempt to double authenticator, authorize,
	// or some other part of the filter chain in delegation cases.
	if delegationTarget.UnprotectedHandler() == nil && c.EnableIndex {
		s.Handler.NonGoRestfulMux.NotFoundHandler(routes.IndexLister{
			StatusCode:   http.StatusNotFound,
			PathProvider: s.listedPathProvider,
		})
	}

	return s, nil
}

```

## NewAPIServerHandler 初始化一个APIServerHandler
staging/src/k8s.io/apiserver/pkg/server/handler.go

```golang
func NewAPIServerHandler(name string, s runtime.NegotiatedSerializer, handlerChainBuilder HandlerChainBuilderFn, notFoundHandler http.Handler) *APIServerHandler {
	nonGoRestfulMux := mux.NewPathRecorderMux(name)
	if notFoundHandler != nil {
		nonGoRestfulMux.NotFoundHandler(notFoundHandler)
	}

	gorestfulContainer := restful.NewContainer()
	gorestfulContainer.Router(restful.CurlyRouter{}) // e.g. for proxy/{kind}/{name}/{*}
	gorestfulContainer.RecoverHandler(func(panicReason interface{}, httpWriter http.ResponseWriter) {
		logStackOnRecover(s, panicReason, httpWriter)
	})
	gorestfulContainer.ServiceErrorHandler(func(serviceErr restful.ServiceError, request *restful.Request, response *restful.Response) {
		serviceErrorHandler(s, serviceErr, request, response)
	})

    // 所有的http请求将由director处理
	director := director{
		name:               name,
		goRestfulContainer: gorestfulContainer,  
		nonGoRestfulMux:    nonGoRestfulMux,
	}

	return &APIServerHandler{
		FullHandlerChain:   handlerChainBuilder(director),  // 使用装饰器模式 装饰handler
		GoRestfulContainer: gorestfulContainer,
		NonGoRestfulMux:    nonGoRestfulMux,
		Director:           director,
	}
}

```

staging/src/k8s.io/apiserver/pkg/server/handler.go

```golang
// 这里的c 是 completedConfig
// 从下面的NewConfig中初始化Config 语句 	BuildHandlerChainFunc:          DefaultBuildHandlerChain, 
// 看出 BuildHandlerChainFunc 就是DefaultBuildHandlerChain
	handlerChainBuilder := func(handler http.Handler) http.Handler {
		return c.BuildHandlerChainFunc(handler, c.Config)
	}

```

staging/src/k8s.io/apiserver/pkg/server/config.go

```golang
func NewConfig(codecs serializer.CodecFactory) *Config {
	defaultHealthChecks := []healthz.HealthChecker{healthz.PingHealthz, healthz.LogHealthz}
	......

	return &Config{
		Serializer:                     codecs,
		BuildHandlerChainFunc:          DefaultBuildHandlerChain,
		NonLongRunningRequestWaitGroup: new(utilwaitgroup.SafeWaitGroup),
		WatchRequestWaitGroup:          &utilwaitgroup.RateLimitedSafeWaitGroup{},
		LegacyAPIGroupPrefixes:         sets.NewString(DefaultLegacyAPIPrefix),
		DisabledPostStartHooks:         sets.NewString(),
		PostStartHooks:                 map[string]PostStartHookConfigEntry{},
		HealthzChecks:                  append([]healthz.HealthChecker{}, defaultHealthChecks...),
		ReadyzChecks:                   append([]healthz.HealthChecker{}, defaultHealthChecks...),
		LivezChecks:                    append([]healthz.HealthChecker{}, defaultHealthChecks...),
		EnableIndex:                    true,
		EnableDiscovery:                true,
		EnableProfiling:                true,
		DebugSocketPath:                "",
		EnableMetrics:                  true,
		MaxRequestsInFlight:            400,
		MaxMutatingRequestsInFlight:    200,
		RequestTimeout:                 time.Duration(60) * time.Second,
		MinRequestTimeout:              1800,
		StorageInitializationTimeout:   time.Minute,
		LivezGracePeriod:               time.Duration(0),
		ShutdownDelayDuration:          time.Duration(0),
		// 1.5MB is the default client request size in bytes
		// the etcd server should accept. See
		// https://github.com/etcd-io/etcd/blob/release-3.4/embed/config.go#L56.
		// A request body might be encoded in json, and is converted to
		// proto when persisted in etcd, so we allow 2x as the largest size
		// increase the "copy" operations in a json patch may cause.
		JSONPatchMaxCopyBytes: int64(3 * 1024 * 1024),
		// 1.5MB is the recommended client request size in byte
		// the etcd server should accept. See
		// https://github.com/etcd-io/etcd/blob/release-3.4/embed/config.go#L56.
		// A request body might be encoded in json, and is converted to
		// proto when persisted in etcd, so we allow 2x as the largest request
		// body size to be accepted and decoded in a write request.
		// If this constant is changed, DefaultMaxRequestSizeBytes in k8s.io/apiserver/pkg/cel/limits.go
		// should be changed to reflect the new value, if the two haven't
		// been wired together already somehow.
		MaxRequestBodyBytes: int64(3 * 1024 * 1024),

		// Default to treating watch as a long-running operation
		// Generic API servers have no inherent long-running subresources
		LongRunningFunc:                     genericfilters.BasicLongRunningRequestCheck(sets.NewString("watch"), sets.NewString()),
		lifecycleSignals:                    lifecycleSignals,
		StorageObjectCountTracker:           flowcontrolrequest.NewStorageObjectCountTracker(),
		ShutdownWatchTerminationGracePeriod: time.Duration(0),

		APIServerID:           id,
		StorageVersionManager: storageversion.NewDefaultManager(),
		TracerProvider:        tracing.NewNoopTracerProvider(),
	}
}


```

## DefaultBuildHandlerChain 使用装饰器为handler添加 认证、授权、审计、限流等功能

staging/src/k8s.io/apiserver/pkg/server/config.go

这个函数是 Kubernetes API Server 的核心请求处理链构建器，通过装饰器模式层层包装原始处理器，实现认证、授权、审计、限流等功能。
请求流向
Client Request → 外层 Filter → ... → 内层 Filter → API

Handler
关键点：代码从下往上包装，但请求从上往下执行。最后添加的 Filter 最先处理请求。

```golang
func DefaultBuildHandlerChain(apiHandler http.Handler, c *Config) http.Handler {
	handler := apiHandler

	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithAuthorization(handler, c.Authorization.Authorizer, c.Serializer)
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "authorization")

	if c.FlowControl != nil {
		workEstimatorCfg := flowcontrolrequest.DefaultWorkEstimatorConfig()
		requestWorkEstimator := flowcontrolrequest.NewWorkEstimator(
			c.StorageObjectCountTracker.Get, c.FlowControl.GetInterestedWatchCount, workEstimatorCfg, c.FlowControl.GetMaxSeats)
		handler = filterlatency.TrackCompleted(handler)
		handler = genericfilters.WithPriorityAndFairness(handler, c.LongRunningFunc, c.FlowControl, requestWorkEstimator, c.RequestTimeout/4)
		handler = filterlatency.TrackStarted(handler, c.TracerProvider, "priorityandfairness")
	} else {
		handler = genericfilters.WithMaxInFlightLimit(handler, c.MaxRequestsInFlight, c.MaxMutatingRequestsInFlight, c.LongRunningFunc)
	}

	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithImpersonation(handler, c.Authorization.Authorizer, c.Serializer)
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "impersonation")

	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithAudit(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator, c.LongRunningFunc)
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "audit")

	failedHandler := genericapifilters.Unauthorized(c.Serializer)
	failedHandler = genericapifilters.WithFailedAuthenticationAudit(failedHandler, c.AuditBackend, c.AuditPolicyRuleEvaluator)

	// WithTracing comes after authentication so we can allow authenticated
	// clients to influence sampling.
	if c.FeatureGate.Enabled(genericfeatures.APIServerTracing) {
		handler = genericapifilters.WithTracing(handler, c.TracerProvider)
	}
	failedHandler = filterlatency.TrackCompleted(failedHandler)
	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithAuthentication(handler, c.Authentication.Authenticator, failedHandler, c.Authentication.APIAudiences, c.Authentication.RequestHeaderConfig)
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "authentication")

	handler = genericfilters.WithCORS(handler, c.CorsAllowedOriginList, nil, nil, nil, "true")

	// WithWarningRecorder must be wrapped by the timeout handler
	// to make the addition of warning headers threadsafe
	handler = genericapifilters.WithWarningRecorder(handler)

	// WithTimeoutForNonLongRunningRequests will call the rest of the request handling in a go-routine with the
	// context with deadline. The go-routine can keep running, while the timeout logic will return a timeout to the client.
	handler = genericfilters.WithTimeoutForNonLongRunningRequests(handler, c.LongRunningFunc)

	handler = genericapifilters.WithRequestDeadline(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator,
		c.LongRunningFunc, c.Serializer, c.RequestTimeout)
	handler = genericfilters.WithWaitGroup(handler, c.LongRunningFunc, c.NonLongRunningRequestWaitGroup)
	if c.ShutdownWatchTerminationGracePeriod > 0 {
		handler = genericfilters.WithWatchTerminationDuringShutdown(handler, c.lifecycleSignals, c.WatchRequestWaitGroup)
	}
	if c.SecureServing != nil && !c.SecureServing.DisableHTTP2 && c.GoawayChance > 0 {
		handler = genericfilters.WithProbabilisticGoaway(handler, c.GoawayChance)
	}
	if c.EnableServiceQuality {
		handler = genericfilters.WithServiceQuality(c.ServiceQualityConfig, handler)
	}
	handler = genericapifilters.WithCacheControl(handler)
	handler = genericfilters.WithHSTS(handler, c.HSTSDirectives)
	if c.ShutdownSendRetryAfter {
		handler = genericfilters.WithRetryAfter(handler, c.lifecycleSignals.NotAcceptingNewRequest.Signaled())
	}
	handler = genericfilters.WithHTTPLogging(handler)
	handler = genericapifilters.WithLatencyTrackers(handler)
	// WithRoutine will execute future handlers in a separate goroutine and serving
	// handler in current goroutine to minimize the stack memory usage. It must be
	// after WithPanicRecover() to be protected from panics.
	if c.FeatureGate.Enabled(genericfeatures.APIServingWithRoutine) {
		handler = routine.WithRoutine(handler, c.LongRunningFunc)
	}
	handler = genericapifilters.WithRequestInfo(handler, c.RequestInfoResolver)
	handler = genericapifilters.WithRequestReceivedTimestamp(handler)
	handler = genericapifilters.WithMuxAndDiscoveryComplete(handler, c.lifecycleSignals.MuxAndDiscoveryComplete.Signaled())
	handler = genericfilters.WithPanicRecovery(handler, c.RequestInfoResolver)
	handler = genericapifilters.WithAuditInit(handler)
	return handler
}


```

## master API Server处理不了的请求，交给notFoundHandler   就是delegationTarget 即apiExtensionsServer.GenericAPIServer 

```go

func NewAPIServerHandler(name string, s runtime.NegotiatedSerializer, handlerChainBuilder HandlerChainBuilderFn, notFoundHandler http.Handler) *APIServerHandler {
	nonGoRestfulMux := mux.NewPathRecorderMux(name)
	if notFoundHandler != nil {
		// master API Server处理不了的请求，交给notFoundHandler   就是delegationTarget 即apiExtensionsServer.GenericAPIServer 
		nonGoRestfulMux.NotFoundHandler(notFoundHandler)
	}

	gorestfulContainer := restful.NewContainer()
	gorestfulContainer.Router(restful.CurlyRouter{}) // e.g. for proxy/{kind}/{name}/{*}
	gorestfulContainer.RecoverHandler(func(panicReason interface{}, httpWriter http.ResponseWriter) {
		logStackOnRecover(s, panicReason, httpWriter)
	})
	gorestfulContainer.ServiceErrorHandler(func(serviceErr restful.ServiceError, request *restful.Request, response *restful.Response) {
		serviceErrorHandler(s, serviceErr, request, response)
	})

	director := director{
		name:               name,
		goRestfulContainer: gorestfulContainer,
		nonGoRestfulMux:    nonGoRestfulMux,
	}

	return &APIServerHandler{
		FullHandlerChain:   handlerChainBuilder(director),
		GoRestfulContainer: gorestfulContainer,
		NonGoRestfulMux:    nonGoRestfulMux,
		Director:           director,
	}
}

```
APIServerHandler 
实现了如下方法：
```golang
func (a *APIServerHandler) ListedPaths() []string {
}

func (a *APIServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// FullHandlerChain:   handlerChainBuilder(director),
	// 交给director处理http请求
	a.FullHandlerChain.ServeHTTP(w, r)
}


func (d director) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path

	// gorestfulContainer处理http请求
	// check to see if our webservices want to claim this path
	for _, ws := range d.goRestfulContainer.RegisteredWebServices() {
		switch {
		case ws.RootPath() == "/apis":
			// if we are exactly /apis or /apis/, then we need special handling in loop.
			// normally these are passed to the nonGoRestfulMux, but if discovery is enabled, it will go directly.
			// We can't rely on a prefix match since /apis matches everything (see the big comment on Director above)
			if path == "/apis" || path == "/apis/" {
				klog.V(5).Infof("%v: %v %q satisfied by gorestful with webservice %v", d.name, req.Method, path, ws.RootPath())
				// don't use servemux here because gorestful servemuxes get messed up when removing webservices
				// TODO fix gorestful, remove TPRs, or stop using gorestful
				d.goRestfulContainer.Dispatch(w, req)
				return
			}

		case strings.HasPrefix(path, ws.RootPath()):
			// ensure an exact match or a path boundary match
			if len(path) == len(ws.RootPath()) || path[len(ws.RootPath())] == '/' {
				klog.V(5).Infof("%v: %v %q satisfied by gorestful with webservice %v", d.name, req.Method, path, ws.RootPath())
				// don't use servemux here because gorestful servemuxes get messed up when removing webservices
				// TODO fix gorestful, remove TPRs, or stop using gorestful
				d.goRestfulContainer.Dispatch(w, req)
				return
			}
		}
	}

	// if we didn't find a match, then we just skip gorestful altogether
	klog.V(5).Infof("%v: %v %q satisfied by nonGoRestful", d.name, req.Method, path)
	// 没有URL能匹配，交给notFoundHandler处理http请求
	d.nonGoRestfulMux.ServeHTTP(w, req)  // func (h *pathHandler) ServeHTTP(w http.ResponseWriter, r *http.Request)
	
}

func (h *pathHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if exactHandler, ok := h.pathToHandler[r.URL.Path]; ok {
		klog.V(5).Infof("%v: %q satisfied by exact match", h.muxName, r.URL.Path)
		exactHandler.ServeHTTP(w, r)
		return
	}

	for _, prefixHandler := range h.prefixHandlers {
		if strings.HasPrefix(r.URL.Path, prefixHandler.prefix) {
			klog.V(5).Infof("%v: %q satisfied by prefix %v", h.muxName, r.URL.Path, prefixHandler.prefix)
			prefixHandler.handler.ServeHTTP(w, r)
			return
		}
	}

	// 交由notFoundHandler处理http请求
	// 交给notFoundHandler   就是delegationTarget 即apiExtensionsServer.GenericAPIServer 
	klog.V(5).Infof("%v: %q satisfied by NotFoundHandler", h.muxName, r.URL.Path)
	h.notFoundHandler.ServeHTTP(w, r)
}
```


---

## DefaultBuildHandlerChain 详细解析

### 整体架构

这个函数是 Kubernetes API Server 的**核心请求处理链构建器**，通过装饰器模式层层包装原始处理器，实现认证、授权、审计、限流等功能。

```
请求流向：
Client Request → 外层 Filter → ... → 内层 Filter → API Handler
```

**关键点**：代码从下往上包装，但请求从上往下执行。最后添加的 Filter 最先处理请求。

### 主要功能模块详解

#### 1. 认证 (Authentication)

```go
handler = genericapifilters.WithAuthentication(
    handler,
    c.Authentication.Authenticator,
    failedHandler,  // 认证失败时执行的处理器
    c.Authentication.APIAudiences,
    c.Authentication.RequestHeaderConfig
)
```

**作用**：

- 验证请求来源的身份
- 支持多种认证方式：TLS 证书、Bearer Token、ServiceAccount、Basic Auth 等
- `failedHandler` 在认证失败时返回 401 Unauthorized

**认证流程**：

1. 提取请求中的凭证（Token、证书等）
2. 调用 Authenticator 验证凭证
3. 验证成功将用户信息存入 Context
4. 验证失败执行 failedHandler

#### 2. 授权 (Authorization)

```go
handler = genericapifilters.WithAuthorization(
    handler,
    c.Authorization.Authorizer,
    c.Serializer
)
```

**作用**：

- 验证已认证用户是否有权限访问特定资源
- 基于 RBAC（Role-Based Access Control）、ABAC 等策略
- 检查用户对资源的 Verb（get、list、create、update、delete 等）权限

**授权流程**：

1. 从 Context 获取用户信息
2. 解析请求的 API 资源、Verb、Namespace 等
3. 调用 Authorizer 授权决策
4. 授权通过继续处理，否则返回 403 Forbidden

#### 3. 审计 (Audit)

```go
handler = genericapifilters.WithAudit(
    handler,
    c.AuditBackend,
    c.AuditPolicyRuleEvaluator,
    c.LongRunningFunc
)
```

**作用**：

- 记录所有 API 请求的操作日志
- 用于安全审计和合规性检查
- 记录内容包括：用户、操作、资源、IP、时间、结果等

**审计日志用途**：

- 安全事件溯源
- 合规性审计
- 异常行为检测

#### 4. 限流与优先级 (Flow Control)

```go
if c.FlowControl != nil {
    handler = genericfilters.WithPriorityAndFairness(
        handler,
        c.LongRunningFunc,
        c.FlowControl,
        requestWorkEstimator,
        c.RequestTimeout/4
    )
} else {
    handler = genericfilters.WithMaxInFlightLimit(
        handler,
        c.MaxRequestsInFlight,
        c.MaxMutatingRequestsInFlight,
        c.LongRunningFunc
    )
}
```

**两种限流模式**：

**a) 优先级与公平性 (Priority & Fairness)**

- 根据请求重要性分配资源
- 支持多个优先级级别
- 防止高优先级请求饿死低优先级请求
- 更精细的流量控制

**b) 最大并发限制 (MaxInFlightLimit)**

- 传统限流机制
- 简单的并发请求数量限制
- 区分读写请求（MaxRequestsInFlight vs MaxMutatingRequestsInFlight）

#### 5. 超时控制 (Timeout)

```go
handler = genericfilters.WithTimeoutForNonLongRunningRequests(
    handler,
    c.LongRunningFunc
)
handler = genericapifilters.WithRequestDeadline(
    handler,
    c.AuditBackend,
    c.AuditPolicyRuleEvaluator,
    c.LongRunningFunc,
    c.Serializer,
    c.RequestTimeout
)
```

**作用**：

- 非长请求（如普通 CRUD）设置超时
- 防止慢请求阻塞系统
- 长请求（如 watch、pod exec）不受超时限制

**超时策略**：

- 默认请求超时：60 秒
- 优先级队列超时：RequestTimeout/4 = 15 秒

#### 6. 模拟 (Impersonation)

```go
handler = genericapifilters.WithImpersonation(
    handler,
    c.Authorization.Authorizer,
    c.Serializer
)
```

**作用**：

- 允许高级用户模拟其他身份执行操作
- 主要用于调试和测试
- 需要特殊权限（impersonate 权限）

**使用场景**：

- 管理员模拟普通用户测试权限
- CI/CD 测试不同角色的访问权限
- 故障排查时复现用户问题

#### 7. 其他关键功能

| 功能                     | 代码                                     | 作用                                               |
| ------------------------ | ---------------------------------------- | -------------------------------------------------- |
| **延迟追踪**       | `filterlatency.TrackCompleted/Started` | 监控各阶段处理耗时，用于性能分析                   |
| **CORS**           | `WithCORS`                             | 跨域资源共享控制，允许 Web 客户端跨域访问          |
| **HSTS**           | `WithHSTS`                             | 强制 HTTPS 安全传输，防止降级攻击                  |
| **Panic 恢复**     | `WithPanicRecovery`                    | 捕获 panic，防止服务崩溃，记录错误日志             |
| **请求信息解析**   | `WithRequestInfo`                      | 解析请求的元数据（用户、操作、资源、Namespace 等） |
| **HTTP 日志**      | `WithHTTPLogging`                      | 记录 HTTP 请求日志（访问日志）                     |
| **缓存控制**       | `WithCacheControl`                     | 设置 HTTP 缓存头，控制客户端缓存行为               |
| **Goaway 概率**    | `WithProbabilisticGoaway`              | 负载均衡优化，平滑连接迁移，方便滚动更新           |
| **WaitGroup**      | `WithWaitGroup`                        | 跟踪进行中的请求，用于优雅关闭                     |
| **Watch 终止**     | `WithWatchTerminationDuringShutdown`   | 关闭时优雅终止长连接                               |
| **重试控制**       | `WithRetryAfter`                       | 关闭期间返回 Retry-After 头                        |
| **警告记录**       | `WithWarningRecorder`                  | 记录警告信息到响应头                               |
| **链路追踪**       | `WithTracing`                          | 分布式追踪支持（需启用特性门控）                   |
| **Goroutine 优化** | `WithRoutine`                          | 减少 Stack 内存使用（需启用特性门控）              |

### 实际请求处理顺序（从外到内）

```
1. WithPanicRecovery                ← 最外层，最先处理，捕获所有 panic
2. WithAuditInit                    ← 初始化审计上下文
3. WithMuxAndDiscoveryComplete      ← 等待路由和发现完成
4. WithRequestReceivedTimestamp     ← 记录请求接收时间
5. WithRequestInfo                  ← 解析请求信息
6. WithRoutine (如果启用)           ← Goroutine 优化
7. WithLatencyTrackers              ← 延迟追踪
8. WithHTTPLogging                  ← HTTP 日志记录
9. WithRetryAfter (关闭时)          ← 返回 Retry-After
10. WithHSTS                        ← HTTPS 强制
11. WithCacheControl                ← 缓存控制
12. WithServiceQuality (如果启用)   ← 服务质量控制
13. WithProbabilisticGoaway (如果启用) ← Goaway 概率
14. WithWatchTermination (如果启用) ← Watch 终止控制
15. WithWaitGroup                   ← 请求追踪
16. WithRequestDeadline             ← 请求截止时间
17. WithTimeoutForNonLongRunningRequests ← 超时控制
18. WithWarningRecorder             ← 警告记录
19. WithCORS                        ← 跨域控制
20. WithAuthentication              ← 认证
21. WithTracing (如果启用)          ← 分布式追踪
22. WithAudit                       ← 审计
23. WithImpersonation               ← 模拟
24. WithAuthorization               ← 授权
25. WithPriorityAndFairness / WithMaxInFlightLimit ← 限流
26. apiHandler                      ← 最内层，最终的业务逻辑处理器
```

### 关键设计模式

#### 1. 洋葱模型（装饰器模式）

```go
handler = filter1(handler)
handler = filter2(handler)
handler = filter3(handler)
// 请求经过：filter1 → filter2 → filter3 → handler
// 响应经过：handler → filter3 → filter2 → filter1
```

**优点**：

- 每个 Filter 职责单一
- 易于组合和扩展
- 符合开闭原则

#### 2. 长请求判断

```go
c.LongRunningFunc(req) // 判断是否为长请求
```

**长请求特征**：

- watch 操作
- portforward/exec/proxy 等流式操作
- 持续时间不确定

**影响**：

- 不受超时限制
- 不计入限流统计
- 可能使用不同的连接管理策略

#### 3. 生命周期信号

```go
c.lifecycleSignals.NotAcceptingNewRequest.Signaled()
c.lifecycleSignals.MuxAndDiscoveryComplete.Signaled()
```

**作用**：

- 实现优雅关闭
- API Server 停止接受新请求时仍处理进行中的请求
- 等待关键组件就绪

**优雅关闭流程**：

1. 停止接受新请求（NotAcceptingNewRequest）
2. 等待进行中的请求完成（WaitGroup）
3. 等待长连接关闭（WatchRequestWaitGroup）
4. 关闭服务器

### 性能优化要点

1. **延迟追踪**：通过 `TrackCompleted/TrackStarted` 监控各阶段耗时，识别性能瓶颈
2. **Goroutine 优化**：`WithRoutine` 减少栈内存使用，适合高并发场景
3. **优先级队列**：确保重要请求优先处理
4. **工作估算**：`requestWorkEstimator` 估算请求成本，合理分配资源

### 安全考虑

1. **认证在最前**：未认证的请求无法访问内部资源
2. **审计全程**：记录所有敏感操作
3. **Panic 恢复**：防止异常导致服务崩溃
4. **超时保护**：防止慢请求攻击
5. **限流保护**：防止系统过载

### 总结

`DefaultBuildHandlerChain` 通过**层层包装**的方式，将横切关注点（认证、授权、审计、限流等）与业务逻辑分离，是**中间件模式**的经典实现。每个 Filter 只负责单一职责，通过组合实现强大的功能。

**设计精髓**：

- 职责分离：每个 Filter 独立维护
- 灵活组合：通过配置启用/禁用功能
- 易于测试：每个 Filter 可单独测试
- 可扩展性：轻松添加新的 Filter

这种设计使得 Kubernetes API Server 能够在保持代码清晰的同时，提供复杂的功能和高度的可靠性。

---

## 洋葱模型详解：请求与响应的流转

### 核心概念

是的，顺序是正确的：

服务器接收到URL请求，先由filter1处理，再filter2处理，再filter3处理，最后handler处理。

响应URL请求时，handler先响应。

```
请求经过：filter1 → filter2 → filter3 → handler
响应经过：handler → filter3 → filter2 → filter1
```

这正是装饰器模式（洋葱模型）的核心特性。

### 可视化流转过程

```
                    请求流向 ↓                    响应流向 ↑
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │ filter1 (最外层)                                           │ │
│  │   ┌─────────────────────────────────────────────────────┐ │ │
│  │   │ filter2                                             │ │ │
│  │   │   ┌───────────────────────────────────────────────┐ │ │ │
│  │   │   │ filter3                                       │ │ │ │
│  │   │   │   ┌─────────────────────────────────────────┐ │ │ │ │
│  │   │   │   │ handler (业务逻辑)                      │ │ │ │ │
│  │   │   │   │   处理请求                               │ │ │ │ │
│  │   │   │   │   返回响应  ◄───────────────────────────┤ │ │ │ │
│  │   │   │   └────────────────────────────────────────┘ │ │ │ │
│  │   │   │         ↑                                     │ │ │ │
│  │   │   └─────────┴─────────────────────────────────────┘ │ │ │
│  │   │             ↑                                       │ │ │
│  │   └─────────────┴───────────────────────────────────────┘ │ │
│  │                 ↑                                         │ │
│  └─────────────────┴───────────────────────────────────────────┘ │
│                    ↑                                             │
└─────────────────────────────────────────────────────────────────┘
```

### 具体代码示例

```go
// 假设有这样三个过滤器
func filter1(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Println("filter1: 请求开始")

        // 调用下一个处理器
        next.ServeHTTP(w, r)

        log.Println("filter1: 响应返回")
    })
}

func filter2(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Println("filter2: 请求开始")

        next.ServeHTTP(w, r)

        log.Println("filter2: 响应返回")
    })
}

func filter3(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Println("filter3: 请求开始")

        next.ServeHTTP(w, r)

        log.Println("filter3: 响应返回")
    })
}

// 构建处理器链（注意：代码从下往上包装）
handler = someBusinessHandler
handler = filter3(handler)  // 最内层
handler = filter2(handler)  // 中间层
handler = filter1(handler)  // 最外层
```

### 实际执行日志

当一个请求进来时，日志输出顺序：

```
filter1: 请求开始    ← 最先执行（最外层）
filter2: 请求开始
filter3: 请求开始
[业务逻辑处理]
filter3: 响应返回    ← 然后层层返回
filter2: 响应返回
filter1: 响应返回    ← 最后返回
```

### 在 DefaultBuildHandlerChain 中的应用

看这段代码：

```go
// 代码从下往上包装
handler = genericapifilters.WithAuthentication(handler, ...)
handler = genericapifilters.WithAuthorization(handler, ...)
handler = genericapifilters.WithAudit(handler, ...)
```

**实际执行顺序：**

| 阶段               | 顺序 | Filter                 |
| ------------------ | ---- | ---------------------- |
| **请求阶段** | 1    | Authorization（授权）  |
|                    | 2    | Authentication（认证） |
|                    | 3    | Audit（审计）          |
|                    | 4    | handler（业务逻辑）    |
| **响应阶段** | 5    | Audit（记录审计日志）  |
|                    | 6    | Authentication（清理） |
|                    | 7    | Authorization（清理）  |

```
请求：Authorization → Authentication → Audit → handler
响应：handler → Audit → Authentication → Authorization
```

### 为什么这样设计？

#### 1. **请求阶段 - 前置处理**

每个 Filter 在调用 `next.ServeHTTP()` 之前执行：

- **认证**：验证用户身份，将用户信息存入 Context
- **授权**：检查用户权限，决定是否继续
- **审计**：记录请求开始时间、请求参数

#### 2. **响应阶段 - 后置处理**

每个 Filter 在 `next.ServeHTTP()` 返回之后执行：

- **审计**：记录响应状态码、耗时
- **添加响应头**：如 Cache-Control、Retry-After
- **清理资源**：释放临时资源
- **记录日志**：记录处理完成

### 实际 Kubernetes 示例

```go
// WithAuthentication 的简化实现
func WithAuthentication(handler http.Handler, auth authenticator.Request, failed http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // ===== 请求阶段：前置处理 =====
        resp, ok := auth.AuthenticateRequest(r)
        if !ok {
            // 认证失败，不调用下一个处理器
            failed.ServeHTTP(w, r)
            return
        }

        // 将用户信息存入 Context
        ctx = WithUser(r.Context(), resp.User)
        r = r.WithContext(ctx)

        // 调用下一个处理器
        handler.ServeHTTP(w, r)

        // ===== 响应阶段：后置处理 =====
        // 可以在这里做一些清理工作
    })
}


// WithAudit 的简化实现
func WithAudit(handler http.Handler, backend audit.Backend) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // ===== 请求阶段 =====
        auditEvent := &audit.Event{
            Stage: audit.StageRequestReceived,
            RequestURI: r.RequestURI,
            Verb: getVerb(r),
            // ... 记录请求信息
        }
        backend.ProcessEvent(auditEvent)

        // 调用下一个处理器
        handler.ServeHTTP(w, r)

        // ===== 响应阶段 =====
        auditEvent = &audit.Event{
            Stage: audit.StageResponseComplete,
            ResponseStatus: getStatus(w),
            // ... 记录响应信息
        }
        backend.ProcessEvent(auditEvent)
    })
}
```

### 关键要点总结

1. **代码包装顺序**：从内到外（handler → filter3 → filter2 → filter1）
2. **请求执行顺序**：从外到内（filter1 → filter2 → filter3 → handler）
3. **响应返回顺序**：从内到外（handler → filter3 → filter2 → filter1）
4. **每个 Filter 都有两个执行点**：
   - `next.ServeHTTP()` 之前：请求预处理
   - `next.ServeHTTP()` 之后：响应后处理

这种设计让每个 Filter 可以在请求和响应的两个阶段都进行处理，提供了极大的灵活性。
