# Kubernetes GenericAPIServer API注册流程详解（第二部分）

本文档详细解释Kubernetes API Server中API资源注册的核心流程，包括Legacy API（如/core/v1）和标准API Group的注册机制。

---

## InstallLegacyAPIGroup - 安装Legacy API组

Legacy API是指Kubernetes早期版本的核心API，使用 `/api`前缀（如 `/api/v1`），而非 `/apis`前缀。

s.installAPIResources(apiPrefix, apiGroupInfo, openAPIModels);

// 核心：安装API资源到RESTful容器
// 这里会为每个资源（如pods、nodes）创建HTTP路由和处理器

```golang
// InstallLegacyAPIGroup 安装Legacy API组（如 /api/v1）
// Legacy API使用 /api 前缀，这是Kubernetes早期的设计，主要用于核心资源如Pod、Node等

func (s *GenericAPIServer) InstallLegacyAPIGroup(apiPrefix string, apiGroupInfo *APIGroupInfo) error {
	// 检查apiPrefix是否在允许的legacy API前缀列表中
	// 这是为了安全性，防止任意注册API前缀
	if !s.legacyAPIGroupPrefixes.Has(apiPrefix) {
		return fmt.Errorf("%q is not in the allowed legacy API prefixes: %v", apiPrefix, s.legacyAPIGroupPrefixes.List())
	}

	// 获取OpenAPI模型，用于生成API文档和Swagger规范
	// OpenAPI模型描述了API的结构、参数、返回值等信息
	openAPIModels, err := s.getOpenAPIModels(apiPrefix, apiGroupInfo)
	if err != nil {
		return fmt.Errorf("unable to get openapi models: %v", err)
	}

	// 核心：安装API资源到RESTful容器
	// 这里会为每个资源（如pods、nodes）创建HTTP路由和处理器
	if err := s.installAPIResources(apiPrefix, apiGroupInfo, openAPIModels); err != nil {
		return err
	}

	legacyRootAPIHandler := discovery.NewLegacyRootAPIHandler(s.discoveryAddresses, s.Serializer, apiPrefix)

	// 将发现处理器包装为聚合发现格式的处理器
	// 聚合发现是Kubernetes 1.27+引入的新格式，可以更高效地发现API资源
	wrapped := discoveryendpoint.WrapAggregatedDiscoveryToHandler(legacyRootAPIHandler, s.AggregatedLegacyDiscoveryGroupManager)

	// 将WebService添加到GoRestfulContainer中
	// GoRestfulContainer是底层HTTP路由容器，基于go-restful框架
	s.Handler.GoRestfulContainer.Add(wrapped.GenerateWebService("/api", metav1.APIVersions{}))

	s.registerStorageReadinessCheck("", apiGroupInfo)

	return nil
}
```

---

## InstallAPIGroups - 安装标准API组

标准API Group使用 `/apis`前缀（如 `/apis/apps/v1`），是Kubernetes推荐的API扩展方式。

```go
// InstallAPIGroups 安装一个或多个API组
// API组是Kubernetes API组织的逻辑单元，如apps、batch、networking.k8s.io等
func (s *GenericAPIServer) InstallAPIGroups(apiGroupInfos ...*APIGroupInfo) error {
	......  // 省略部分前置检查代码

	// 获取OpenAPI模型，用于API文档生成
	openAPIModels, err := s.getOpenAPIModels(APIGroupPrefix, apiGroupInfos...)
	if err != nil {
		return fmt.Errorf("unable to get openapi models: %v", err)
	}

	// 遍历所有API组信息，为每个组安装资源
	for _, apiGroupInfo := range apiGroupInfos {
		// 核心：安装API资源
		// APIGroupInfo包含了组内所有版本的资源信息和存储配置
		if err := s.installAPIResources(APIGroupPrefix, apiGroupInfo, openAPIModels); err != nil {
			return fmt.Errorf("unable to install api resources: %v", err)
		}

		// 设置API发现机制
		// 在 /apis/<groupName> 路径添加处理器，用于列举该组支持的所有版本
		// 例如 GET /apis/apps 返回 {"kind": "APIGroup", "name": "apps", "versions": [...]}
		apiVersionsForDiscovery := []metav1.GroupVersionForDiscovery{}
		.....
	}
	return nil
}
```

---

## installAPIResources - 安装API资源

这是API注册的核心函数，负责为每个API版本创建路由和处理器。


discoveryAPIResources, r, err := apiGroupVersion.InstallREST(s.Handler.GoRestfulContainer)

    // 核心：安装REST路由！！！
		// 这是整个API注册流程中最关键的调用
		// 它会为每个资源创建HTTP路由和处理器

```go
// installAPIResources 为指定API组安装资源路由和处理器
// apiPrefix: API前缀，如 "/api" 或 "/apis"
// apiGroupInfo: 包含API组所有版本和资源的配置信息
// typeConverter: 用于管理字段的类型转换

func (s *GenericAPIServer) installAPIResources(apiPrefix string, apiGroupInfo *APIGroupInfo, typeConverter managedfields.TypeConverter) error {
	var resourceInfos []*storageversion.ResourceInfo

	// 遍历API组中的每个版本（如apps组的v1和v1beta1）
	// PrioritizedVersions是按优先级排序的版本列表
	for _, groupVersion := range apiGroupInfo.PrioritizedVersions {
		// 如果该版本没有任何资源，跳过并记录警告
		// 这可能是废弃版本或空版本
		if len(apiGroupInfo.VersionedResourcesStorageMap[groupVersion.Version]) == 0 {
			klog.Warningf("Skipping API %v because it has no resources.", groupVersion)
			continue
		}

		// 获取API组版本对象
		// APIGroupVersion封装了单个API版本的所有配置
		apiGroupVersion, err := s.getAPIGroupVersion(apiGroupInfo, groupVersion, apiPrefix)
		if err != nil {
			return err
		}

		// 设置Options对象的外部版本
		// Options对象用于传递操作选项，如ListOptions、CreateOptions等
		if apiGroupInfo.OptionsExternalVersion != nil {
			apiGroupVersion.OptionsExternalVersion = apiGroupInfo.OptionsExternalVersion
		}

		// 设置类型转换器，用于处理多版本对象的转换
		apiGroupVersion.TypeConverter = typeConverter

		// 设置最大请求体大小限制
		apiGroupVersion.MaxRequestBodyBytes = s.maxRequestBodyBytes

		// 核心：安装REST路由！！！
		// 这是整个API注册流程中最关键的调用
		// 它会为每个资源创建HTTP路由和处理器
		discoveryAPIResources, r, err := apiGroupVersion.InstallREST(s.Handler.GoRestfulContainer)

		if err != nil {
			return fmt.Errorf("unable to setup API %v: %v", apiGroupInfo, err)
		}
		resourceInfos = append(resourceInfos, r...)

		// 将资源信息添加到聚合发现管理器
		// 聚合发现是Kubernetes的新发现机制，用于高效地枚举API资源
		if apiPrefix == APIGroupPrefix {
			// 标准API组（/apis）使用AggregatedDiscoveryGroupManager
			s.AggregatedDiscoveryGroupManager.AddGroupVersion(
				groupVersion.Group,
				apidiscoveryv2.APIVersionDiscovery{
					Freshness: apidiscoveryv2.DiscoveryFreshnessCurrent, // 标记为当前版本
					Version:   groupVersion.Version,
					Resources: discoveryAPIResources, // 该版本的所有资源
				},
			)
		} else {
			// Legacy API（/api）使用AggregatedLegacyDiscoveryGroupManager
			// Legacy资源只有一个组版本，优先级默认为0
			s.AggregatedLegacyDiscoveryGroupManager.AddGroupVersion(
				groupVersion.Group,
				apidiscoveryv2.APIVersionDiscovery{
					Freshness: apidiscoveryv2.DiscoveryFreshnessCurrent,
					Version:   groupVersion.Version,
					Resources: discoveryAPIResources,
				},
			)
		}
	}

	// 注册存储销毁函数
	// 当API Server关闭时，用于清理资源
	s.RegisterDestroyFunc(apiGroupInfo.destroyStorage)

	// 如果启用了StorageVersionAPI和APIServerIdentity特性门控
	// 则注册资源信息到StorageVersionManager
	// StorageVersion用于跟踪资源在etcd中存储的版本
	if s.FeatureGate.Enabled(features.StorageVersionAPI) &&
		s.FeatureGate.Enabled(features.APIServerIdentity) {
		// API安装发生在开始监听请求之前
		// 因此在这里注册ResourceInfo是安全的
		// 处理器会阻塞写请求，直到目标资源的存储版本更新完成
		s.StorageVersionManager.AddResourceInfo(resourceInfos...)
	}

	return nil
}
```

---

## InstallREST - 安装REST路由

为单个API版本创建RESTful WebService。

```go
// InstallREST 为API组版本创建REST路由
// container: GoRestful容器，用于注册WebService
// 返回: 发现资源列表、存储版本信息列表、错误
func (g *APIGroupVersion) InstallREST(container *restful.Container) ([]apidiscoveryv2.APIResourceDiscovery, []*storageversion.ResourceInfo, error) {
	// 构建API路径，格式: /<root>/<group>/<version>
	// 例如: /apis/apps/v1 或 /api/v1
	prefix := path.Join(g.Root, g.GroupVersion.Group, g.GroupVersion.Version)

	// 创建API安装器
	// APIInstaller负责实际的资源路由注册
	installer := &APIInstaller{
		group:             g,        // API组版本配置
		prefix:            prefix,   // 路由前缀
		minRequestTimeout: g.MinRequestTimeout, // 最小请求超时时间
	}

	// 核心：调用installer.Install()安装所有资源！！！
	// 这会为Storage中的每个资源创建HTTP路由和处理器
	apiResources, resourceInfos, ws, registrationErrors := installer.Install()

	// 创建API版本发现处理器
	// 用于处理 GET /apis/<group>/<version> 请求
	// 返回该版本支持的所有资源列表
	versionDiscoveryHandler := discovery.NewAPIVersionHandler(g.Serializer, g.GroupVersion, staticLister{apiResources})

	// 将发现处理器添加到WebService
	versionDiscoveryHandler.AddToWebService(ws)

	// 将WebService添加到容器中
	container.Add(ws)

	// 将资源转换为发现格式
	aggregatedDiscoveryResources, err := ConvertGroupVersionIntoToDiscovery(apiResources)
	if err != nil {
		registrationErrors = append(registrationErrors, err)
	}

	return aggregatedDiscoveryResources, removeNonPersistedResources(resourceInfos), utilerrors.NewAggregate(registrationErrors)
}
```

---

## APIInstaller.Install() - 安装器主入口

位于：`staging/src/k8s.io/apiserver/pkg/endpoints/installer.go`

这是资源路由注册的核心实现。

### 步骤1：遍历Storage并注册处理器

```go
// Install 为API组中的所有资源注册路由
// 返回: API资源列表、存储版本信息、WebService、错误列表
func (a *APIInstaller) Install() ([]metav1.APIResource, []*storageversion.ResourceInfo, *restful.WebService, []error) {
	var apiResources []metav1.APIResource        // API资源元数据列表
	var resourceInfos []*storageversion.ResourceInfo // 存储版本信息列表
	var errors []error                             // 错误列表

	// 创建新的WebService
	// WebService是go-restful框架的概念，用于组织一组相关的路由
	ws := a.newWebService()

	// 按确定（排序）的顺序注册路径，以获得确定的swagger规范
	// 这确保每次生成的API文档都是一致的
	paths := make([]string, len(a.group.Storage))
	var i int = 0
	for path := range a.group.Storage {
		paths[i] = path
		i++
	}
	sort.Strings(paths)

	// 遍历所有资源路径（如"pods", "nodes", "services"等）
	// a.group.Storage是资源名到Storage实现的映射
	for _, path := range paths {
		// 核心：为每个资源注册处理器！！！
		// 这是最重要的调用，会创建GET/POST/PUT/DELETE等HTTP路由
		apiResource, resourceInfo, err := a.registerResourceHandlers(path, a.group.Storage[path], ws)
		if err != nil {
			errors = append(errors, fmt.Errorf("error in registering resource: %s, %v", path, err))
		}
		if apiResource != nil {
			apiResources = append(apiResources, *apiResource)
		}
		if resourceInfo != nil {
			resourceInfos = append(resourceInfos, resourceInfo)
		}
	}

	return apiResources, resourceInfos, ws, errors
}
```

---

## registerResourceHandlers - 注册资源处理器（最核心的函数）

这是整个API注册流程中最核心、最复杂的函数。它根据Storage支持的接口，动态创建RESTful路由。

位于：`staging/src/k8s.io/apiserver/pkg/endpoints/installer.go`

```go
// registerResourceHandlers 为单个资源注册所有HTTP处理器
// path: 资源路径，如"pods"、"pods/status"、"pods/log"等
// storage: Storage实现，封装了资源的CRUD操作
// ws: WebService，用于注册路由
func (a *APIInstaller) registerResourceHandlers(path string, storage rest.Storage, ws *restful.WebService) (*metav1.APIResource, *storageversion.ResourceInfo, error) {
	admit := a.group.Admit  // 准入控制器配置

	// 确定Options对象的外部版本
	optionsExternalVersion := a.group.GroupVersion
	if a.group.OptionsExternalVersion != nil {
		optionsExternalVersion = *a.group.OptionsExternalVersion
	}

	// 解析资源路径，区分主资源和子资源
	// 例如："pods/status" 会解析为 resource="pods", subresource="status"
	resource, subresource, err := splitSubresource(path)
	if err != nil {
		return nil, nil, err
	}

	// 获取组和版本信息
	group, version := a.group.GroupVersion.Group, a.group.GroupVersion.Version

	// 获取资源的Kind（资源类型）
	// 例如：Pod、Node、Service等
	fqKindToRegister, err := GetResourceKind(a.group.GroupVersion, storage, a.group.Typer)
	if err != nil {
		return nil, nil, err
	}

	// 创建版本化对象的实例
	// 用于序列化/反序列化请求和响应
	versionedPtr, err := a.group.Creater.New(fqKindToRegister)
	if err != nil {
		return nil, nil, err
	}
	defaultVersionedObject := indirectArbitraryPointer(versionedPtr)
	kind := fqKindToRegister.Kind
	isSubresource := len(subresource) > 0

	// ============================================================
	// 确定资源是否是命名空间作用域的
	// ============================================================
	var namespaceScoped bool
	if isSubresource {
		// 子资源的作用域由父资源决定
		parentStorage, ok := a.group.Storage[resource]
		if !ok {
			return nil, nil, fmt.Errorf("missing parent storage: %q", resource)
		}
		scoper, ok := parentStorage.(rest.Scoper)
		if !ok {
			return nil, nil, fmt.Errorf("%q must implement scoper", resource)
		}
		namespaceScoped = scoper.NamespaceScoped()
	} else {
		// 主资源通过实现Scoper接口声明是否是命名空间作用域
		scoper, ok := storage.(rest.Scoper)
		if !ok {
			return nil, nil, fmt.Errorf("%q must implement scoper", resource)
		}
		namespaceScoped = scoper.NamespaceScoped()
	}

	// ============================================================
	// 通过类型断言检测Storage支持的接口
	// ============================================================
	// 这些接口决定了资源支持哪些HTTP动词和方法
	// 例如：实现了Creater接口就支持POST创建，实现了Lister就支持GET列表

	creater, isCreater := storage.(rest.Creater)  // 创建单个资源
	namedCreater, isNamedCreater := storage.(rest.NamedCreater)  // 按名称创建
	lister, isLister := storage.(rest.Lister)  // 列出资源
	getter, isGetter := storage.(rest.Getter)  // 获取单个资源
	getterWithOptions, isGetterWithOptions := storage.(rest.GetterWithOptions)  // 带选项获取
	gracefulDeleter, isGracefulDeleter := storage.(rest.GracefulDeleter)  // 优雅删除
	collectionDeleter, isCollectionDeleter := storage.(rest.CollectionDeleter)  // 删除集合
	updater, isUpdater := storage.(rest.Updater)  // 更新资源
	patcher, isPatcher := storage.(rest.Patcher)  // 补丁更新
	watcher, isWatcher := storage.(rest.Watcher)  // 监听资源
	connecter, isConnecter := storage.(rest.Connecter)  // 连接资源（如exec、portforward）
	storageMeta, isMetadata := storage.(rest.StorageMetadata)  // 存储元数据
	storageVersionProvider, isStorageVersionProvider := storage.(rest.StorageVersionProvider)  // 存储版本
	gvAcceptor, _ := storage.(rest.GroupVersionAcceptor)  // 组版本接受器
	if !isMetadata {
		storageMeta = defaultStorageMetadata{}
	}

	// 如果实现了NamedCreater，则也支持创建
	if isNamedCreater {
		isCreater = true
	}

	// ============================================================
	// 创建各种版本化对象
	// ============================================================
	var versionedList interface{}
	if isLister {
		// 创建列表对象，如PodList
		list := lister.NewList()
		listGVKs, _, err := a.group.Typer.ObjectKinds(list)
		if err != nil {
			return nil, nil, err
		}
		versionedListPtr, err := a.group.Creater.New(a.group.GroupVersion.WithKind(listGVKs[0].Kind))
		if err != nil {
			return nil, nil, err
		}
		versionedList = indirectArbitraryPointer(versionedListPtr)
	}

	// 创建各种Options对象，用于传递操作参数
	versionedListOptions, err := a.group.Creater.New(optionsExternalVersion.WithKind("ListOptions"))
	if err != nil {
		return nil, nil, err
	}
	versionedCreateOptions, err := a.group.Creater.New(optionsExternalVersion.WithKind("CreateOptions"))
	if err != nil {
		return nil, nil, err
	}
	versionedPatchOptions, err := a.group.Creater.New(optionsExternalVersion.WithKind("PatchOptions"))
	if err != nil {
		return nil, nil, err
	}
	versionedUpdateOptions, err := a.group.Creater.New(optionsExternalVersion.WithKind("UpdateOptions"))
	if err != nil {
		return nil, nil, err
	}

	var versionedDeleteOptions runtime.Object
	var versionedDeleterObject interface{}
	deleteReturnsDeletedObject := false
	if isGracefulDeleter {
		// 创建DeleteOptions对象
		versionedDeleteOptions, err = a.group.Creater.New(optionsExternalVersion.WithKind("DeleteOptions"))
		if err != nil {
			return nil, nil, err
		}
		versionedDeleterObject = indirectArbitraryPointer(versionedDeleteOptions)

		// 检查删除操作是否返回完整的被删除对象
		if mayReturnFullObjectDeleter, ok := storage.(rest.MayReturnFullObjectDeleter); ok {
			deleteReturnsDeletedObject = mayReturnFullObjectDeleter.DeleteReturnsDeletedObject()
		}
	}

	// 创建Status对象，用于返回操作状态
	versionedStatusPtr, err := a.group.Creater.New(optionsExternalVersion.WithKind("Status"))
	if err != nil {
		return nil, nil, err
	}
	versionedStatus := indirectArbitraryPointer(versionedStatusPtr)

	var (
		getOptions             runtime.Object
		versionedGetOptions    runtime.Object
		getOptionsInternalKind schema.GroupVersionKind
		getSubpath             bool
	)
	if isGetterWithOptions {
		// 处理带选项的GET请求（如获取子路径）
		getOptions, getSubpath, _ = getterWithOptions.NewGetOptions()
		getOptionsInternalKinds, _, err := a.group.Typer.ObjectKinds(getOptions)
		if err != nil {
			return nil, nil, err
		}
		getOptionsInternalKind = getOptionsInternalKinds[0]
		versionedGetOptions, err = a.group.Creater.New(a.group.GroupVersion.WithKind(getOptionsInternalKind.Kind))
		if err != nil {
			versionedGetOptions, err = a.group.Creater.New(optionsExternalVersion.WithKind(getOptionsInternalKind.Kind))
			if err != nil {
				return nil, nil, err
			}
		}
		isGetter = true
	}

	// 创建WatchEvent对象，用于watch事件
	var versionedWatchEvent interface{}
	if isWatcher {
		versionedWatchEventPtr, err := a.group.Creater.New(a.group.GroupVersion.WithKind("WatchEvent"))
		if err != nil {
			return nil, nil, err
		}
		versionedWatchEvent = indirectArbitraryPointer(versionedWatchEventPtr)
	}

	// 处理Connect选项（用于exec、portforward等操作）
	var (
		connectOptions             runtime.Object
		versionedConnectOptions    runtime.Object
		connectOptionsInternalKind schema.GroupVersionKind
		connectSubpath             bool
	)
	if isConnecter {
		connectOptions, connectSubpath, _ = connecter.NewConnectOptions()
		if connectOptions != nil {
			connectOptionsInternalKinds, _, err := a.group.Typer.ObjectKinds(connectOptions)
			if err != nil {
				return nil, nil, err
			}

			connectOptionsInternalKind = connectOptionsInternalKinds[0]
			versionedConnectOptions, err = a.group.Creater.New(a.group.GroupVersion.WithKind(connectOptionsInternalKind.Kind))
			if err != nil {
				versionedConnectOptions, err = a.group.Creater.New(optionsExternalVersion.WithKind(connectOptionsInternalKind.Kind))
				if err != nil {
					return nil, nil, err
				}
			}
		}
	}

	// 只有同时支持watch和list的资源才允许watch列表操作
	allowWatchList := isWatcher && isLister

	// 定义路径参数
	nameParam := ws.PathParameter("name", "name of the "+kind).DataType("string")
	pathParam := ws.PathParameter("path", "path to the resource").DataType("string")

	params := []*restful.Parameter{}
	actions := []action{}

	// ============================================================
	// 确定资源的Kind
	// ============================================================
	var resourceKind string
	kindProvider, ok := storage.(rest.KindProvider)
	if ok {
		resourceKind = kindProvider.Kind()
	} else {
		resourceKind = kind
	}

	// 检查Lister是否实现了TableConvertor
	// TableConvertor用于将资源转换为表格格式（如kubectl get输出）
	tableProvider, isTableProvider := storage.(rest.TableConvertor)
	if isLister && !isTableProvider {
		return nil, nil, fmt.Errorf("%q must implement TableConvertor", resource)
	}

	// ============================================================
	// 创建APIResource元数据
	// ============================================================
	var apiResource metav1.APIResource
	if utilfeature.DefaultFeatureGate.Enabled(features.StorageVersionHash) &&
		isStorageVersionProvider &&
		storageVersionProvider.StorageVersion() != nil {
		versioner := storageVersionProvider.StorageVersion()
		gvk, err := getStorageVersionKind(versioner, storage, a.group.Typer)
		if err != nil {
			return nil, nil, err
		}
		// 计算存储版本的哈希值，用于验证存储版本的一致性
		apiResource.StorageVersionHash = discovery.StorageVersionHash(gvk.Group, gvk.Version, gvk.Kind)
	}

	// ============================================================
	// 根据作用域类型创建路由
	// ============================================================
	switch {
	case !namespaceScoped:
		// ========================================
		// 非命名空间作用域的资源（如Node、PersistentVolume等）
		// ========================================
		resourcePath := resource          // 资源路径，如 "nodes"
		resourceParams := params          // 资源级参数
		itemPath := resourcePath + "/{name}"  // 单个资源路径，如 "nodes/{name}"
		nameParams := append(params, nameParam)  // 名称参数
		proxyParams := append(nameParams, pathParam)  // 代理参数（用于proxy子资源）
		suffix := ""
		if isSubresource {
			// 处理子资源路径
			suffix = "/" + subresource
			itemPath = itemPath + suffix  // 如 "nodes/{name}/status"
			resourcePath = itemPath
			resourceParams = nameParams
		}
		apiResource.Name = path
		apiResource.Namespaced = false
		apiResource.Kind = resourceKind
		namer := handlers.ContextBasedNaming{
			Namer:         a.group.Namer,
			ClusterScoped: true,
		}

		// 为标准REST动词添加处理器（GET、PUT、POST、DELETE）
		// 在资源路径添加动作: /api/apiVersion/resource
		actions = appendIf(actions, action{request.MethodList, resourcePath, resourceParams, namer, false}, isLister)
		actions = appendIf(actions, action{request.MethodPost, resourcePath, resourceParams, namer, false}, isCreater)
		actions = appendIf(actions, action{request.MethodDeleteCollection, resourcePath, resourceParams, namer, false}, isCollectionDeleter)
		// 已废弃（1.11版本）：watch列表
		actions = appendIf(actions, action{request.MethodWatchList, "watch/" + resourcePath, resourceParams, namer, false}, allowWatchList)

		// 在单项路径添加动作: /api/apiVersion/resource/{name}
		actions = appendIf(actions, action{request.MethodGet, itemPath, nameParams, namer, false}, isGetter)
		if getSubpath {
			// 支持获取子路径（用于获取文件内容等场景）
			actions = appendIf(actions, action{request.MethodGet, itemPath + "/{path:*}", proxyParams, namer, false}, isGetter)
		}
		actions = appendIf(actions, action{request.MethodPut, itemPath, nameParams, namer, false}, isUpdater)
		actions = appendIf(actions, action{request.MethodPatch, itemPath, nameParams, namer, false}, isPatcher)
		actions = appendIf(actions, action{request.MethodDelete, itemPath, nameParams, namer, false}, isGracefulDeleter)
		// 已废弃（1.11版本）：watch单项
		actions = appendIf(actions, action{request.MethodWatch, "watch/" + itemPath, nameParams, namer, false}, isWatcher)
		actions = appendIf(actions, action{request.MethodConnect, itemPath, nameParams, namer, false}, isConnecter)
		actions = appendIf(actions, action{request.MethodConnect, itemPath + "/{path:*}", proxyParams, namer, false}, isConnecter && connectSubpath)

	default:
		// ========================================
		// 命名空间作用域的资源（如Pod、Service等）
		// ========================================
		namespaceParamName := "namespaces"
		// 命名空间参数
		namespaceParam := ws.PathParameter("namespace", "object name and auth scope, such as for teams and projects").DataType("string")
		namespacedPath := namespaceParamName + "/{namespace}/" + resource  // 如 "namespaces/{namespace}/pods"
		namespaceParams := []*restful.Parameter{namespaceParam}

		resourcePath := namespacedPath
		resourceParams := namespaceParams
		itemPath := namespacedPath + "/{name}"  // 如 "namespaces/{namespace}/pods/{name}"
		nameParams := append(namespaceParams, nameParam)
		proxyParams := append(nameParams, pathParam)
		itemPathSuffix := ""
		if isSubresource {
			itemPathSuffix = "/" + subresource
			itemPath = itemPath + itemPathSuffix
			resourcePath = itemPath
			resourceParams = nameParams
		}
		apiResource.Name = path
		apiResource.Namespaced = true
		apiResource.Kind = resourceKind
		namer := handlers.ContextBasedNaming{
			Namer:         a.group.Namer,
			ClusterScoped: false,
		}

		// 资源级操作
		actions = appendIf(actions, action{request.MethodList, resourcePath, resourceParams, namer, false}, isLister)
		actions = appendIf(actions, action{request.MethodPost, resourcePath, resourceParams, namer, false}, isCreater)
		actions = appendIf(actions, action{request.MethodDeleteCollection, resourcePath, resourceParams, namer, false}, isCollectionDeleter)
		actions = appendIf(actions, action{request.MethodWatchList, "watch/" + resourcePath, resourceParams, namer, false}, allowWatchList)

		// 单项级操作
		actions = appendIf(actions, action{request.MethodGet, itemPath, nameParams, namer, false}, isGetter)
		if getSubpath {
			actions = appendIf(actions, action{request.MethodGet, itemPath + "/{path:*}", proxyParams, namer, false}, isGetter)
		}
		actions = appendIf(actions, action{request.MethodPut, itemPath, nameParams, namer, false}, isUpdater)
		actions = appendIf(actions, action{request.MethodPatch, itemPath, nameParams, namer, false}, isPatcher)
		actions = appendIf(actions, action{request.MethodDelete, itemPath, nameParams, namer, false}, isGracefulDeleter)
		actions = appendIf(actions, action{request.MethodWatch, "watch/" + itemPath, nameParams, namer, false}, isWatcher)
		actions = appendIf(actions, action{request.MethodConnect, itemPath, nameParams, namer, false}, isConnecter)
		actions = appendIf(actions, action{request.MethodConnect, itemPath + "/{path:*}", proxyParams, namer, false}, isConnecter && connectSubpath)

		// ========================================
		// 跨命名空间的操作（仅对非子资源）
		// ========================================
		// 例如：通过 GET /api/v1/pods 列出所有命名空间的所有Pod
		if !isSubresource {
			actions = appendIf(actions, action{request.MethodList, resource, params, namer, true}, isLister)
			actions = appendIf(actions, action{request.MethodWatchList, "watch/" + resource, params, namer, true}, allowWatchList)
		}
	}

	// ============================================================
	// 创建StorageVersion资源信息
	// ============================================================
	var resourceInfo *storageversion.ResourceInfo
	if utilfeature.DefaultFeatureGate.Enabled(features.StorageVersionAPI) &&
		utilfeature.DefaultFeatureGate.Enabled(features.APIServerIdentity) &&
		isStorageVersionProvider &&
		storageVersionProvider.StorageVersion() != nil {

		versioner := storageVersionProvider.StorageVersion()
		encodingGVK, err := getStorageVersionKind(versioner, storage, a.group.Typer)
		if err != nil {
			return nil, nil, err
		}
		// 获取可解码的版本列表
		decodableVersions := []schema.GroupVersion{}
		if a.group.ConvertabilityChecker != nil {
			decodableVersions = a.group.ConvertabilityChecker.VersionsForGroupKind(fqKindToRegister.GroupKind())
		}

		resourceInfo = &storageversion.ResourceInfo{
			GroupResource: schema.GroupResource{
				Group:    a.group.GroupVersion.Group,
				Resource: apiResource.Name,
			},
			EncodingVersion: encodingGVK.GroupVersion().String(),
			// 先记录EquivalentResourceMapper而不是立即计算DecodableVersions
			// 因为我们需要先完成API安装才能知道等效的API
			EquivalentResourceMapper: a.group.EquivalentResourceRegistry,

			DirectlyDecodableVersions: decodableVersions,

			ServedVersions: a.group.AllServedVersionsByResource[path],
		}
	}

	// ============================================================
	// 配置媒体类型
	// ============================================================
	// 创建路由并为动作添加处理器
	for _, s := range a.group.Serializer.SupportedMediaTypes() {
		if len(s.MediaTypeSubType) == 0 || len(s.MediaTypeType) == 0 {
			return nil, nil, fmt.Errorf("all serializers in the group Serializer must have MediaTypeType and MediaTypeSubType set: %s", s.MediaType)
		}
	}
	mediaTypes, streamMediaTypes := negotiation.MediaTypesForSerializer(a.group.Serializer)
	allMediaTypes := append(mediaTypes, streamMediaTypes...)
	ws.Produces(allMediaTypes...)

	kubeVerbs := map[string]struct{}{}

	// ============================================================
	// 创建RequestScope（请求作用域）
	// ============================================================
	// RequestScope包含了处理HTTP请求所需的所有配置和工具
	reqScope := handlers.RequestScope{
		Serializer:      a.group.Serializer,      // 序列化器
		ParameterCodec:  a.group.ParameterCodec,  // 参数编码器
		Creater:         a.group.Creater,         // 对象创建器
		Convertor:       a.group.Convertor,       // 对象转换器
		Defaulter:       a.group.Defaulter,       // 默认值设置器
		Typer:           a.group.Typer,           // 类型识别器
		UnsafeConvertor: a.group.UnsafeConvertor, // 非安全转换器
		Authorizer:      a.group.Authorizer,      // 授权器

		EquivalentResourceMapper: a.group.EquivalentResourceRegistry,  // 等效资源映射器

		// TODO: 检查storage上的接口
		TableConvertor: tableProvider,  // 表格转换器

		// TODO: 这对于跨组子资源似乎有误。它假设子资源和其父资源在同一组版本中。
		Resource:    a.group.GroupVersion.WithResource(resource),  // 资源GVR
		Subresource: subresource,  // 子资源名称
		Kind:        fqKindToRegister,  // 资源GVK

		AcceptsGroupVersionDelegate: gvAcceptor,  // 组版本接受器

		HubGroupVersion: schema.GroupVersion{Group: fqKindToRegister.Group, Version: runtime.APIVersionInternal},  // 内部版本

		MetaGroupVersion: metav1.SchemeGroupVersion,  // 元数据组版本

		MaxRequestBodyBytes: a.group.MaxRequestBodyBytes,  // 最大请求体大小
	}
	if a.group.MetaGroupVersion != nil {
		reqScope.MetaGroupVersion = *a.group.MetaGroupVersion
	}

	// ============================================================
	// 配置字段重置策略
	// ============================================================
	// 策略可能通过重置字段值来忽略对某些字段的更改
	// 例如：spec资源策略应重置status，status子资源策略应重置spec
	var resetFieldsFilter map[fieldpath.APIVersion]fieldpath.Filter
	resetFieldsStrategy, isResetFieldsStrategy := storage.(rest.ResetFieldsStrategy)
	if isResetFieldsStrategy {
		resetFieldsFilter = fieldpath.NewExcludeFilterSetMap(resetFieldsStrategy.GetResetFields())
	}
	if resetFieldsStrategy, isResetFieldsFilterStrategy := storage.(rest.ResetFieldsFilterStrategy); isResetFieldsFilterStrategy {
		if isResetFieldsStrategy {
			return nil, nil, fmt.Errorf("may not implement both ResetFieldsStrategy and ResetFieldsFilterStrategy")
		}
		resetFieldsFilter = resetFieldsStrategy.GetResetFieldsFilter()
	}

	// 创建字段管理器（用于Server-Side Apply）
	reqScope.FieldManager, err = managedfields.NewDefaultFieldManager(
		a.group.TypeConverter,
		a.group.UnsafeConvertor,
		a.group.Defaulter,
		a.group.Creater,
		fqKindToRegister,
		reqScope.HubGroupVersion,
		subresource,
		resetFieldsFilter,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create field manager: %v", err)
	}

	// ============================================================
	// 为每个动作创建HTTP路由
	// ============================================================
	for _, action := range actions {
		producedObject := storageMeta.ProducesObject(action.Verb)
		if producedObject == nil {
			producedObject = defaultVersionedObject
		}
		reqScope.Namer = action.Namer

		// 确定请求作用域（cluster、namespace、resource）
		requestScope := "cluster"
		var namespaced string
		var operationSuffix string
		if apiResource.Namespaced {
			requestScope = "namespace"
			namespaced = "Namespaced"
		}
		if strings.HasSuffix(action.Path, "/{path:*}") {
			requestScope = "resource"
			operationSuffix = operationSuffix + "WithPath"
		}
		if strings.Contains(action.Path, "/{name}") || action.Verb == request.MethodPost {
			requestScope = "resource"
		}
		if action.AllNamespaces {
			requestScope = "cluster"
			operationSuffix = operationSuffix + "ForAllNamespaces"
			namespaced = ""
		}

		// 将HTTP动词转换为Kube动词（用于发现）
		if kubeVerb, found := toDiscoveryKubeVerb[action.Verb]; found {
			if len(kubeVerb) != 0 {
				kubeVerbs[kubeVerb] = struct{}{}
			}
		} else {
			return nil, nil, fmt.Errorf("unknown action verb for discovery: %s", action.Verb)
		}

		routes := []*restful.RouteBuilder{}

		// 如果是子资源，kind应该是父资源的kind
		if isSubresource {
			parentStorage, ok := a.group.Storage[resource]
			if !ok {
				return nil, nil, fmt.Errorf("missing parent storage: %q", resource)
			}

			fqParentKind, err := GetResourceKind(a.group.GroupVersion, parentStorage, a.group.Typer)
			if err != nil {
				return nil, nil, err
			}
			kind = fqParentKind.Kind
		}

		verbOverrider, needOverride := storage.(StorageMetricsOverride)

		// 累积端点级别的警告
		var (
			warnings       []string
			deprecated     bool
			removedRelease string
		)

		// 检查资源是否已废弃
		{
			versionedPtrWithGVK := versionedPtr.DeepCopyObject()
			versionedPtrWithGVK.GetObjectKind().SetGroupVersionKind(fqKindToRegister)
			currentMajor, currentMinor, _ := deprecation.MajorMinor(versioninfo.Get())
			deprecated = deprecation.IsDeprecated(versionedPtrWithGVK, currentMajor, currentMinor)
			if deprecated {
				removedRelease = deprecation.RemovedRelease(versionedPtrWithGVK)
				warnings = append(warnings, deprecation.WarningMessage(versionedPtrWithGVK))
			}
		}

		// ============================================================
		// 根据HTTP动词创建路由
		// ============================================================
		switch action.Verb {
		case request.MethodGet:  // 获取单个资源
			var handler restful.RouteFunction
			if isGetterWithOptions {
				handler = restfulGetResourceWithOptions(getterWithOptions, reqScope, isSubresource)
			} else {
				handler = restfulGetResource(getter, reqScope)
			}

			// 包装指标收集
			if needOverride {
				handler = metrics.InstrumentRouteFunc(verbOverrider.OverrideMetricsVerb(action.Verb), group, version, resource, subresource, requestScope, metrics.APIServerComponent, deprecated, removedRelease, handler)
			} else {
				handler = metrics.InstrumentRouteFunc(action.Verb, group, version, resource, subresource, requestScope, metrics.APIServerComponent, deprecated, removedRelease, handler)
			}
			handler = utilwarning.AddWarningsHandler(handler, warnings)

			doc := "read the specified " + kind
			if isSubresource {
				doc = "read " + subresource + " of the specified " + kind
			}
			// 创建GET路由
			route := ws.GET(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed. Defaults to 'false' unless the user-agent indicates a browser or command-line HTTP tool (curl and wget).")).
				Operation("read"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
				Returns(http.StatusOK, "OK", producedObject).
				Writes(producedObject)
			if isGetterWithOptions {
				if err := AddObjectParams(ws, route, versionedGetOptions); err != nil {
					return nil, nil, err
				}
			}
			addParams(route, action.Params)
			routes = append(routes, route)

		case request.MethodList:  // 列出资源
			doc := "list objects of kind " + kind
			if isSubresource {
				doc = "list " + subresource + " of objects of kind " + kind
			}
			// 列表处理器同时支持watch
			handler := metrics.InstrumentRouteFunc(action.Verb, group, version, resource, subresource, requestScope, metrics.APIServerComponent, deprecated, removedRelease, restfulListResource(lister, watcher, reqScope, false, a.minRequestTimeout))
			handler = utilwarning.AddWarningsHandler(handler, warnings)
			route := ws.GET(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed. Defaults to 'false' unless the user-agent indicates a browser or command-line HTTP tool (curl and wget).")).
				Operation("list"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), allMediaTypes...)...).
				Returns(http.StatusOK, "OK", versionedList).
				Writes(versionedList)
			if err := AddObjectParams(ws, route, versionedListOptions); err != nil {
				return nil, nil, err
			}
			switch {
			case isLister && isWatcher:
				doc := "list or watch objects of kind " + kind
				if isSubresource {
					doc = "list or watch " + subresource + " of objects of kind " + kind
				}
				route.Doc(doc)
			case isWatcher:
				doc := "watch objects of kind " + kind
				if isSubresource {
					doc = "watch " + subresource + "of objects of kind " + kind
				}
				route.Doc(doc)
			}
			addParams(route, action.Params)
			routes = append(routes, route)

		case request.MethodPut:  // 更新资源
			doc := "replace the specified " + kind
			if isSubresource {
				doc = "replace " + subresource + " of the specified " + kind
			}
			handler := metrics.InstrumentRouteFunc(action.Verb, group, version, resource, subresource, requestScope, metrics.APIServerComponent, deprecated, removedRelease, restfulUpdateResource(updater, reqScope, admit))
			handler = utilwarning.AddWarningsHandler(handler, warnings)
			route := ws.PUT(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed. Defaults to 'false' unless the user-agent indicates a browser or command-line HTTP tool (curl and wget).")).
				Operation("replace"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
				Returns(http.StatusOK, "OK", producedObject).
				Returns(http.StatusCreated, "Created", producedObject).
				Reads(defaultVersionedObject).
				Writes(producedObject)
			if err := AddObjectParams(ws, route, versionedUpdateOptions); err != nil {
				return nil, nil, err
			}
			addParams(route, action.Params)
			routes = append(routes, route)

		case request.MethodPatch:  // 补丁更新
			doc := "partially update the specified " + kind
			if isSubresource {
				doc = "partially update " + subresource + " of the specified " + kind
			}
			// 支持的补丁类型
			supportedTypes := []string{
				string(types.JSONPatchType),           // JSON Patch
				string(types.MergePatchType),          // Merge Patch
				string(types.StrategicMergePatchType), // Strategic Merge Patch（Kubernetes特有）
				string(types.ApplyYAMLPatchType),      // Server-Side Apply（YAML）
			}
			if utilfeature.DefaultFeatureGate.Enabled(features.CBORServingAndStorage) {
				supportedTypes = append(supportedTypes, string(types.ApplyCBORPatchType))
			}
			handler := metrics.InstrumentRouteFunc(action.Verb, group, version, resource, subresource, requestScope, metrics.APIServerComponent, deprecated, removedRelease, restfulPatchResource(patcher, reqScope, admit, supportedTypes))
			handler = utilwarning.AddWarningsHandler(handler, warnings)
			route := ws.PATCH(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed. Defaults to 'false' unless the user-agent indicates a browser or command-line HTTP tool (curl and wget).")).
				Consumes(supportedTypes...).
				Operation("patch"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
				Returns(http.StatusOK, "OK", producedObject).
				Returns(http.StatusCreated, "Created", producedObject).
				Reads(metav1.Patch{}).
				Writes(producedObject)
			if err := AddObjectParams(ws, route, versionedPatchOptions); err != nil {
				return nil, nil, err
			}
			addParams(route, action.Params)
			routes = append(routes, route)

		case request.MethodPost:  // 创建资源
			var handler restful.RouteFunction
			if isNamedCreater {
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
			route := ws.POST(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed. Defaults to 'false' unless the user-agent indicates a browser or command-line HTTP tool (curl and wget).")).
				Operation("create"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
				Returns(http.StatusOK, "OK", producedObject).
				Returns(http.StatusCreated, "Created", producedObject).
				Returns(http.StatusAccepted, "Accepted", producedObject).
				Reads(defaultVersionedObject).
				Writes(producedObject)
			if err := AddObjectParams(ws, route, versionedCreateOptions); err != nil {
				return nil, nil, err
			}
			addParams(route, action.Params)
			routes = append(routes, route)

		case request.MethodDelete:  // 删除单个资源
			article := GetArticleForNoun(kind, " ")
			doc := "delete" + article + kind
			if isSubresource {
				doc = "delete " + subresource + " of" + article + kind
			}
			deleteReturnType := versionedStatus
			if deleteReturnsDeletedObject {
				deleteReturnType = producedObject
			}
			handler := metrics.InstrumentRouteFunc(action.Verb, group, version, resource, subresource, requestScope, metrics.APIServerComponent, deprecated, removedRelease, restfulDeleteResource(gracefulDeleter, isGracefulDeleter, reqScope, admit))
			handler = utilwarning.AddWarningsHandler(handler, warnings)
			route := ws.DELETE(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed. Defaults to 'false' unless the user-agent indicates a browser or command-line HTTP tool (curl and wget).")).
				Operation("delete"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
				Writes(deleteReturnType).
				Returns(http.StatusOK, "OK", deleteReturnType).
				Returns(http.StatusAccepted, "Accepted", deleteReturnType)
			if isGracefulDeleter {
				route.Reads(versionedDeleterObject)
				route.ParameterNamed("body").Required(false)
				if err := AddObjectParams(ws, route, versionedDeleteOptions); err != nil {
					return nil, nil, err
				}
			}
			addParams(route, action.Params)
			routes = append(routes, route)

		case request.MethodDeleteCollection:  // 删除资源集合
			doc := "delete collection of " + kind
			if isSubresource {
				doc = "delete collection of " + subresource + " of a " + kind
			}
			handler := metrics.InstrumentRouteFunc(action.Verb, group, version, resource, subresource, requestScope, metrics.APIServerComponent, deprecated, removedRelease, restfulDeleteCollection(collectionDeleter, isCollectionDeleter, reqScope, admit))
			handler = utilwarning.AddWarningsHandler(handler, warnings)
			route := ws.DELETE(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed. Defaults to 'false' unless the user-agent indicates a browser or command-line HTTP tool (curl and wget).")).
				Operation("deletecollection"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
				Writes(versionedStatus).
				Returns(http.StatusOK, "OK", versionedStatus)
			if isCollectionDeleter {
				route.Reads(versionedDeleterObject)
				route.ParameterNamed("body").Required(false)
				if err := AddObjectParams(ws, route, versionedDeleteOptions); err != nil {
					return nil, nil, err
				}
			}
			if err := AddObjectParams(ws, route, versionedListOptions, "watch", "allowWatchBookmarks"); err != nil {
				return nil, nil, err
			}
			addParams(route, action.Params)
			routes = append(routes, route)

		// 已废弃（1.11版本）
		case request.MethodWatch:  // 监听单个资源
			doc := "watch changes to an object of kind " + kind
			if isSubresource {
				doc = "watch changes to " + subresource + " of an object of kind " + kind
			}
			doc += ". deprecated: use the 'watch' parameter with a list operation instead, filtered to a single item with the 'fieldSelector' parameter."
			handler := metrics.InstrumentRouteFunc(action.Verb, group, version, resource, subresource, requestScope, metrics.APIServerComponent, deprecated, removedRelease, restfulListResource(lister, watcher, reqScope, true, a.minRequestTimeout))
			handler = utilwarning.AddWarningsHandler(handler, warnings)
			route := ws.GET(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed. Defaults to 'false' unless the user-agent indicates a browser or command-line HTTP tool (curl and wget).")).
				Operation("watch"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(allMediaTypes...).
				Returns(http.StatusOK, "OK", versionedWatchEvent).
				Writes(versionedWatchEvent)
			if err := AddObjectParams(ws, route, versionedListOptions); err != nil {
				return nil, nil, err
			}
			addParams(route, action.Params)
			routes = append(routes, route)

		// 已废弃（1.11版本）
		case request.MethodWatchList:  // 监听资源列表
			doc := "watch individual changes to a list of " + kind
			if isSubresource {
				doc = "watch individual changes to a list of " + subresource + " of " + kind
			}
			doc += ". deprecated: use the 'watch' parameter with a list operation instead."
			handler := metrics.InstrumentRouteFunc(action.Verb, group, version, resource, subresource, requestScope, metrics.APIServerComponent, deprecated, removedRelease, restfulListResource(lister, watcher, reqScope, true, a.minRequestTimeout))
			handler = utilwarning.AddWarningsHandler(handler, warnings)
			route := ws.GET(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed. Defaults to 'false' unless the user-agent indicates a browser or command-line HTTP tool (curl and wget).")).
				Operation("watch"+namespaced+kind+strings.Title(subresource)+"List"+operationSuffix).
				Produces(allMediaTypes...).
				Returns(http.StatusOK, "OK", versionedWatchEvent).
				Writes(versionedWatchEvent)
			if err := AddObjectParams(ws, route, versionedListOptions); err != nil {
				return nil, nil, err
			}
			addParams(route, action.Params)
			routes = append(routes, route)

		case request.MethodConnect:  // 连接操作（exec、portforward等）
			for _, method := range connecter.ConnectMethods() {
				connectProducedObject := storageMeta.ProducesObject(method)
				if connectProducedObject == nil {
					connectProducedObject = "string"
				}
				doc := "connect " + method + " requests to " + kind
				if isSubresource {
					doc = "connect " + method + " requests to " + subresource + " of " + kind
				}
				handler := metrics.InstrumentRouteFunc(action.Verb, group, version, resource, subresource, requestScope, metrics.APIServerComponent, deprecated, removedRelease, restfulConnectResource(connecter, reqScope, admit, path, isSubresource))
				handler = utilwarning.AddWarningsHandler(handler, warnings)
				route := ws.Method(method).Path(action.Path).
					To(handler).
					Doc(doc).
					Operation("connect" + strings.Title(strings.ToLower(method)) + namespaced + kind + strings.Title(subresource) + operationSuffix).
					Produces("*/*").
					Consumes("*/*").
					Writes(connectProducedObject)
				if versionedConnectOptions != nil {
					if err := AddObjectParams(ws, route, versionedConnectOptions); err != nil {
						return nil, nil, err
					}
				}
				addParams(route, action.Params)
				routes = append(routes, route)

				// 将ConnectMethods转换为kube verbs
				if kubeVerb, found := toDiscoveryKubeVerb[method]; found {
					if len(kubeVerb) != 0 {
						kubeVerbs[kubeVerb] = struct{}{}
					}
				}
			}

		default:
			return nil, nil, fmt.Errorf("unrecognized action verb: %s", action.Verb)
		}

		// ============================================================
		// 将路由添加到WebService
		// ============================================================
		for _, route := range routes {
			// 设置路由元数据（GVK）
			route.Metadata(RouteMetaGVK, metav1.GroupVersionKind{
				Group:   reqScope.Kind.Group,
				Version: reqScope.Kind.Version,
				Kind:    reqScope.Kind.Kind,
			})
			// 设置路由元数据（动作）
			route.Metadata(RouteMetaAction, strings.ToLower(action.Verb))
			// 将路由添加到WebService
			ws.Route(route)
		}
		// 注意：添加自定义处理器时需要更新 GetAuthorizerAttributes()
	}

	// ============================================================
	// 填充APIResource元数据
	// ============================================================
	apiResource.Verbs = make([]string, 0, len(kubeVerbs))
	for kubeVerb := range kubeVerbs {
		apiResource.Verbs = append(apiResource.Verbs, kubeVerb)
	}
	sort.Strings(apiResource.Verbs)

	// 获取短名称（如po、svc等）
	if shortNamesProvider, ok := storage.(rest.ShortNamesProvider); ok {
		apiResource.ShortNames = shortNamesProvider.ShortNames()
	}

	// 获取分类（如all）
	if categoriesProvider, ok := storage.(rest.CategoriesProvider); ok {
		apiResource.Categories = categoriesProvider.Categories()
	}

	// 获取单数名称（仅主资源）
	if !isSubresource {
		singularNameProvider, ok := storage.(rest.SingularNameProvider)
		if !ok {
			return nil, nil, fmt.Errorf("resource %s must implement SingularNameProvider", resource)
		}
		apiResource.SingularName = singularNameProvider.GetSingularName()
	}

	// 获取GVK信息
	if gvkProvider, ok := storage.(rest.GroupVersionKindProvider); ok {
		gvk := gvkProvider.GroupVersionKind(a.group.GroupVersion)
		apiResource.Group = gvk.Group
		apiResource.Version = gvk.Version
		apiResource.Kind = gvk.Kind
	}

	// ============================================================
	// 记录GVR和对应的GVK映射关系
	// ============================================================
	// 这对于API转换和发现非常重要
	a.group.EquivalentResourceRegistry.RegisterKindFor(reqScope.Resource, reqScope.Subresource, fqKindToRegister)

	return &apiResource, resourceInfo, nil
}
```

---

## 总结

### API注册流程概览

```
InstallLegacyAPIGroup / InstallAPIGroups
    ↓
installAPIResources
    ↓
InstallREST (APIGroupVersion)
    ↓
Install() (APIInstaller)
    ↓
registerResourceHandlers (核心！！！)
    ↓ 创建HTTP路由
    ↓ GET /api/v1/pods
    ↓ POST /api/v1/pods
    ↓ GET /api/v1/pods/{name}
    ↓ PUT /api/v1/pods/{name}
    ↓ DELETE /api/v1/pods/{name}
    ↓ PATCH /api/v1/pods/{name}
    ↓ GET /api/v1/namespaces/{namespace}/pods
    ↓ ...等等
```

### 关键数据结构

| 结构体               | 作用                                |
| -------------------- | ----------------------------------- |
| `GenericAPIServer` | API服务器主结构，包含所有配置和状态 |
| `APIGroupInfo`     | API组信息，包含所有版本和资源配置   |
| `APIGroupVersion`  | 单个API版本的配置                   |
| `APIInstaller`     | API安装器，负责创建路由             |
| `RequestScope`     | 请求作用域，包含处理请求的所有工具  |
| `rest.Storage`     | 存储接口，定义资源的CRUD操作        |

### 关键接口

| 接口                  | 方法               | HTTP动词     | 说明               |
| --------------------- | ------------------ | ------------ | ------------------ |
| `Creater`           | Create()           | POST         | 创建资源           |
| `Lister`            | List()             | GET          | 列出资源           |
| `Getter`            | Get()              | GET          | 获取单个资源       |
| `Updater`           | Update()           | PUT          | 更新资源           |
| `Patcher`           | Update()           | PATCH        | 补丁更新           |
| `GracefulDeleter`   | Delete()           | DELETE       | 删除资源           |
| `CollectionDeleter` | DeleteCollection() | DELETE       | 删除集合           |
| `Watcher`           | Watch()            | GET + watch  | 监听资源           |
| `Connecter`         | Connect()          | CONNECT/POST | 连接操作（exec等） |

### 路由模式

#### 命名空间作用域资源（如Pod）

```
GET    /api/v1/namespaces/{namespace}/pods           # 列出Pod
POST   /api/v1/namespaces/{namespace}/pods           # 创建Pod
GET    /api/v1/namespaces/{namespace}/pods/{name}    # 获取Pod
PUT    /api/v1/namespaces/{namespace}/pods/{name}    # 更新Pod
PATCH  /api/v1/namespaces/{namespace}/pods/{name}    # 补丁Pod
DELETE /api/v1/namespaces/{namespace}/pods/{name}    # 删除Pod
GET    /api/v1/pods                                  # 列出所有Pod（跨namespace）
```

#### 集群作用域资源（如Node）

```
GET    /api/v1/nodes          # 列出Node
POST   /api/v1/nodes          # 创建Node
GET    /api/v1/nodes/{name}   # 获取Node
PUT    /api/v1/nodes/{name}   # 更新Node
PATCH  /api/v1/nodes/{name}   # 补丁Node
DELETE /api/v1/nodes/{name}   # 删除Node
```

#### 子资源（如Pod的status）

```
GET    /api/v1/namespaces/{namespace}/pods/{name}/status
PUT    /api/v1/namespaces/{namespace}/pods/{name}/status
GET    /api/v1/namespaces/{namespace}/pods/{name}/log
GET    /api/v1/namespaces/{namespace}/pods/{name}/exec
POST   /api/v1/namespaces/{namespace}/pods/{name}/exec
```
输出1
