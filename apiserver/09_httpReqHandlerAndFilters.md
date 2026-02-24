# http request处理过程

## 1 Default Filters(包括登录和鉴权)

### 1.1 NewAPIServerHandler 初始化一个APIServerHandler

```golang
staging/src/k8s.io/apiserver/pkg/server/handler.go
func NewAPIServerHandler(name string, s runtime.NegotiatedSerializer, handlerChainBuilder HandlerChainBuilderFn, notFoundHandler http.Handler) *APIServerHandler {
    ......

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

staging/src/k8s.io/apiserver/pkg/server/handler.go
// 这里的c 是 completedConfig
// 从下面的NewConfig中初始化Config 语句 	BuildHandlerChainFunc:          DefaultBuildHandlerChain, 
// 看出 BuildHandlerChainFunc 就是DefaultBuildHandlerChain

handlerChainBuilder := func(handler http.Handler) http.Handler {
    return c.BuildHandlerChainFunc(handler, c.Config)
}
```

### 1.2 handlerChainBuilder的创建

DefaultBuildHandlerChain 使用装饰器为handler添加 认证、授权、审计、限流等功能，返回一个**http.Handler**

staging/src/k8s.io/apiserver/pkg/server/config.go

这个函数是 Kubernetes API Server 的核心请求处理链构建器，通过装饰器模式层层包装原始处理器，实现认证、授权、审计、限流等功能。
请求流向
Client Request → 外层 Filter → ... → 内层 Filter → API

Handler
关键点：代码从下往上包装，但请求从上往下执行。最后添加的 Filter 最先处理请求。
// DefaultBuildHandlerChain 函数通过层层包装（wrapper pattern）构建一个完整的 HTTP 处理器链。请求从外层向内层传递，响应则从内层向外层返回

```go
// DefaultBuildHandlerChain 函数通过层层包装（wrapper pattern）构建一个完整的 HTTP 处理器链。请求从外层向内层传递，响应则从内层向外层返回
func DefaultBuildHandlerChain(apiHandler http.Handler, c *Config) http.Handler {
	handler := apiHandler

	// 11 鉴权 检查已认证的用户是否有权限执行该操作
	handler = genericapifilters.WithAuthorization(handler, c.Authorization.Authorizer, c.Serializer)
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "authorization")

	// 10 限流层
	.......

	// 审计
	handler = genericapifilters.WithAudit(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator, c.LongRunningFunc)
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "audit")

    ......
	// 认证层 验证客户端的身份（Token、证书等）
	handler = genericapifilters.WithAuthentication(handler, c.Authentication.Authenticator, failedHandler, c.Authentication.APIAudiences, c.Authentication.RequestHeaderConfig)
	handler = filterlatency.TrackStarted(handler, c.TracerProvider, "authentication")
    
    ......

	// 2 并发控制 将后续处理在独立的goroutine中执行，减少栈内存使用
	if c.FeatureGate.Enabled(genericfeatures.APIServingWithRoutine) {
		handler = routine.WithRoutine(handler, c.LongRunningFunc)
	}
	// 1 基础层
	handler = genericapifilters.WithRequestInfo(handler, c.RequestInfoResolver)
	handler = genericapifilters.WithRequestReceivedTimestamp(handler)
	handler = genericapifilters.WithMuxAndDiscoveryComplete(handler, c.lifecycleSignals.MuxAndDiscoveryComplete.Signaled())
	handler = genericfilters.WithPanicRecovery(handler, c.RequestInfoResolver) // panic
	handler = genericapifilters.WithAuditInit(handler)                         // 初始化审计上下文
	return handler
}
```




## 2 En/Decoder & Conversion 、Admission
Request's       =>> External Version API Resource => Internal Version API Resource  
http payload    =>> Golang Type Instance         => Golang Type Instance  

### 2.0 为APIGroupVersion设定Serializer参数

```go
func (s *GenericAPIServer) newAPIGroupVersion(apiGroupInfo *APIGroupInfo, groupVersion schema.GroupVersion) *genericapi.APIGroupVersion {

	allServedVersionsByResource := map[string][]string{}
	for version, resourcesInVersion := range apiGroupInfo.VersionedResourcesStorageMap {
		for resource := range resourcesInVersion {
			if len(groupVersion.Group) == 0 {
				allServedVersionsByResource[resource] = append(allServedVersionsByResource[resource], version)
			} else {
				allServedVersionsByResource[resource] = append(allServedVersionsByResource[resource], fmt.Sprintf("%s/%s", groupVersion.Group, version))
			}
		}
	}

	return &genericapi.APIGroupVersion{
		GroupVersion:                groupVersion,
		AllServedVersionsByResource: allServedVersionsByResource,
		MetaGroupVersion:            apiGroupInfo.MetaGroupVersion,

		ParameterCodec:        apiGroupInfo.ParameterCodec,
		Serializer:            apiGroupInfo.NegotiatedSerializer,  // 设置序列化器
		Creater:               apiGroupInfo.Scheme,               
		Convertor:             apiGroupInfo.Scheme,                // 指定转换器
		ConvertabilityChecker: apiGroupInfo.Scheme,
		UnsafeConvertor:       runtime.UnsafeObjectConvertor(apiGroupInfo.Scheme),
		Defaulter:             apiGroupInfo.Scheme,
		Typer:                 apiGroupInfo.Scheme,
		Namer:                 runtime.Namer(meta.NewAccessor()),

		EquivalentResourceRegistry: s.EquivalentResourceRegistry,

		Admit:             s.admissionControl,
		MinRequestTimeout: s.minRequestTimeout,
		Authorizer:        s.Authorizer,
	}
}

```


### 2.1 做一个reqScope
staging/src/k8s.io/apiserver/pkg/endpoints/installer.go
```go
	// 构建请求处理的上下文
	reqScope := handlers.RequestScope{
		Serializer:      a.group.Serializer, // 序列化器： 对象-> JSON/YAML
		ParameterCodec:  a.group.ParameterCodec,
		Creater:         a.group.Creater,
		Convertor:       a.group.Convertor, // 安全的类型转换，用于对象在不同 API 版本间转换
        ......
	}

```

### 2.2 在制作req handler的时候，使用上述reqScope
staging/src/k8s.io/apiserver/pkg/endpoints/installer.go 
```go
        // 为post请求创建路由
		case request.MethodPost: // Create a resource.  为post请求创建路由
			var handler restful.RouteFunction
			// 选择处理器函数
			if isNamedCreater {
                // ！！！！！! 制作req handler的时候，使用上述reqScope ！！！！！！
				handler = restfulCreateNamedResource(namedCreater, reqScope, admit)
			} else {
				handler = restfulCreateResource(creater, reqScope, admit)
			}
			handler = metrics.InstrumentRouteFunc(action.Verb, group, version, resource, subresource, requestScope, metrics.APIServerComponent, deprecated, removedRelease, handler)
			handler = utilwarning.AddWarningsHandler(handler, warnings)
			article := GetArticleForNoun(kind, " ")
			doc := "create" + article + kind
			if isSubresource {
				doc = "create " + subresource + " of" + article + kind
			}
			// 构建路由对象  ??? 这种用法不太熟悉
			route := ws.POST(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed. Defaults to 'false' unless the user-agent indicates a browser or command-line HTTP tool (curl and wget).")).
				Operation("create"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
				Returns(http.StatusOK, "OK", producedObject).
				// TODO: in some cases, the API may return a v1.Status instead of the versioned object
				// but currently go-restful can't handle multiple different objects being returned.
				Returns(http.StatusCreated, "Created", producedObject).
				Returns(http.StatusAccepted, "Accepted", producedObject).
				Reads(defaultVersionedObject).
				Writes(producedObject)
			if err := AddObjectParams(ws, route, versionedCreateOptions); err != nil {
				return nil, nil, err
			}
			addParams(route, action.Params)
			// 注册路由
			routes = append(routes, route)
```


### 2.3 在handller内部使用Seriallizer得到encoder/decoder进行编解码

staging/src/k8s.io/apiserver/pkg/endpoints/handlers/create.go  

客户端请求体 (JSON)
      ↓
  [反序列化]
      ↓
  客户端版本对象 (apps/v1.Deployment)
      ↓
  [版本转换]
      ↓
  内部版本对象 (apps.Deployment)
      ↓
  obj (内部版本对象)

```go
func createHandler(r rest.NamedCreater, scope *RequestScope, admit admission.Interface, includeName bool) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()

		......
		
		decodeSerializer := s.Serializer // 序列化器
		if validationDirective == metav1.FieldValidationWarn || validationDirective == metav1.FieldValidationStrict {
			decodeSerializer = s.StrictSerializer
		}

		// 创建解码器
		decoder := scope.Serializer.DecoderToVersion(decodeSerializer, scope.HubGroupVersion)
		span.AddEvent("About to convert to expected version")
		// Decode执行反序列化和版本转换
		obj, gvk, err := decoder.Decode(body, &defaultGVK, original)
		if err != nil {
			strictError, isStrictError := runtime.AsStrictDecodingError(err)
			switch {
			case isStrictError && obj != nil && validationDirective == metav1.FieldValidationWarn:
				addStrictDecodingWarnings(req.Context(), strictError.Errors())
			case isStrictError && validationDirective == metav1.FieldValidationIgnore:
				klog.Warningf("unexpected strict error when field validation is set to ignore")
				fallthrough
			default:
				err = transformDecodeError(scope.Typer, err, original, gvk, body)
				scope.err(err, w, req)
				return
			}
		}
        
        ......
		
	}
}
```


## 3 ETCD Store  Request Handler使用 Store响应 http request 

### 3.1 定义REST结构体、 NewRest 返回 *REST：主 Deployment 资源（完整对象）
```go
type REST struct {
	// 内嵌的genericregistry.Store结构体来复用其属性和方法
	*genericregistry.Store
}


// 创建 Deployment

//   kubectl create deployment nginx --image=nginx

//   处理流程：

//   1. HTTP 请求
//      POST /apis/apps/v1/namespaces/default/deployments

//   2. API Server Handler
//      → createHandler(rest.NamedCreater, ...)

//   3. 准入控制
//      → validatingAdmission
//      → mutatingAdmission

//   4. REST.Create
//      → store.Create(ctx, name, obj, ...)

//   5. genericregistry.Store.Create
//      a. 调用 PrepareForCreate
//         deployment.Strategy.PrepareForCreate(ctx, obj)
//         → 设置默认值

//      b. 调用 Validate
//         deployment.Strategy.Validate(ctx, obj)
//         → 验证 selector、replicas、template

//      c. 写入 etcd
//         storage.Create(ctx, obj)
//         → 序列化为 JSON
//         → 写入 /registry/deployments/default/nginx

//   6. 返回响应
//      201 Created
//      {
//        "apiVersion": "apps/v1",
//        "kind": "Deployment",
//        "metadata": { "name": "nginx", ... },
//        "spec": { ... },
//        "status": { ... }
//      }

// NewREST returns a RESTStorage object that will work against deployments.
// 返回三个 REST 对象：
//   1. *REST：主 Deployment 资源（完整对象）
//   2. *StatusREST：Deployment 的 status 子资源
//   3. *RollbackREST：Deployment 的 rollback 子资源

func NewREST(optsGetter generic.RESTOptionsGetter) (*REST, *StatusREST, *RollbackREST, error) {
	store := &genericregistry.Store{
		NewFunc:                   func() runtime.Object { return &apps.Deployment{} },
		NewListFunc:               func() runtime.Object { return &apps.DeploymentList{} },
		DefaultQualifiedResource:  apps.Resource("deployments"),
		SingularQualifiedResource: apps.Resource("deployment"),

		// 策略对象（核心）
		CreateStrategy:      deployment.Strategy,
		UpdateStrategy:      deployment.Strategy,
		DeleteStrategy:      deployment.Strategy,
		ResetFieldsStrategy: deployment.Strategy,

		TableConvertor: printerstorage.TableConvertor{TableGenerator: printers.NewTableGenerator().With(printersinternal.AddHandlers)},
	}
	options := &generic.StoreOptions{RESTOptions: optsGetter}
	if err := store.CompleteWithOptions(options); err != nil {
		return nil, nil, nil, err
	}

	statusStore := *store
	statusStore.UpdateStrategy = deployment.StatusStrategy
	statusStore.ResetFieldsStrategy = deployment.StatusStrategy
	return &REST{store}, &StatusREST{store: &statusStore}, &RollbackREST{store: store}, nil
}
```


```go
staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go 
type Store struct {
     ......
	// CreateStrategy implements resource-specific behavior during creation.
	CreateStrategy rest.RESTCreateStrategy


	// UpdateStrategy implements resource-specific behavior during updates.
	UpdateStrategy rest.RESTUpdateStrategy

	// DeleteStrategy implements resource-specific behavior during deletion.
	DeleteStrategy rest.RESTDeleteStrategy

	ResetFieldsStrategy rest.ResetFieldsStrategy

}

func (e *Store) List(ctx context.Context, options *metainternalversion.ListOptions) (runtime.Object, error)

func (e *Store) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) 

func (e *Store) Update(ctx context.Context, name string, objInfo rest.UpdatedObjectInfo, createValidation rest.ValidateObjectFunc, updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) 

func (e *Store) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) 

func (e *Store) Delete(ctx context.Context, name string, deleteValidation rest.ValidateObjectFunc, options *metav1.DeleteOptions) (runtime.Object, bool, error) 

func (e *Store) Watch(ctx context.Context, options *metainternalversion.ListOptions) (watch.Interface, error) 
```

### 3.2 Request Handler使用Store响应Http Request

staging/src/k8s.io/apiserver/pkg/endpoints/handlers/create.go 
```go

		requestFunc := func() (runtime.Object, error) {
			return r.Create(  // 这里的r就是Store结构体
				ctx,
				name,
				obj,
				rest.AdmissionToValidateObjectFunc(admit, admissionAttributes, scope),
				options,
			)
		}
```


### 3.3 策略设计模式
  把"做什么"（业务逻辑）和"怎么做"（具体实现）分离

  - Store 知道"做什么"：先准备，再验证，最后存储； 定义好处理流程。
  - Strategy 知道"怎么做"：Deployment 怎么准备，Pod 怎么准备  具体如何处理，交个每个API Object的stragety来实现

```go 
CreateStrategy rest.RESTCreateStrategy
RESTCreateStrategy 是一个接口

type RESTCreateStrategy interface {
	runtime.ObjectTyper

	names.NameGenerator

	// NamespaceScoped returns true if the object must be within a namespace.
	NamespaceScoped() bool

	PrepareForCreate(ctx context.Context, obj runtime.Object)

	Validate(ctx context.Context, obj runtime.Object) field.ErrorList

	WarningsOnCreate(ctx context.Context, obj runtime.Object) []string

	Canonicalize(obj runtime.Object)
}

pkg/registry/apps/deployment/strategy.go  

deploymentStrategy 实现了 CreateStrategy接口
var Strategy = deploymentStrategy{legacyscheme.Scheme, names.SimpleNameGenerator}


func (deploymentStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	deployment := obj.(*apps.Deployment)
	deployment.Status = apps.DeploymentStatus{}
	deployment.Generation = 1

	pod.DropDisabledTemplateFields(&deployment.Spec.Template, nil)
}


func (deploymentStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	deployment := obj.(*apps.Deployment)
	opts := pod.GetValidationOptionsFromPodTemplate(&deployment.Spec.Template, nil)
	return appsvalidation.ValidateDeployment(deployment, opts)
}


pkg/registry/apps/statefulset/strategy.go
statefulset 也实现了自己的 statefulSetStrategy()

func (statefulSetStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	statefulSet := obj.(*apps.StatefulSet)
	// create cannot set status
	statefulSet.Status = apps.StatefulSetStatus{}

	statefulSet.Generation = 1

	dropStatefulSetDisabledFields(statefulSet, nil)
	pod.DropDisabledTemplateFields(&statefulSet.Spec.Template, nil)
}

......

```
