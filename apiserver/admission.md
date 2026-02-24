#  Kubernetes Admission Plugins 注册与配置总体概览
简化的时间线

  时间线
    │
    ├─ 程序启动
    │   └─ main() 被调用
    │
    ├─ 创建命令对象（NewOptions() 在这里被调用）
    │   └─ NewAPIServerCommand()
    │       └─ NewServerRunOptions()
    │           └─ NewOptions()
    │               └─ NewAdmissionOptions()
    │                   └─ RegisterAllAdmissionPlugins()  ← 注册插件
    │
    ├─ 注册命令行参数（AddFlags 被调用） AddFlags() 将命令行参数与这些字段绑定，当用户执行命令时，参数值会被自动写入对应字段。
    │   └─ s.Admission.AddFlags(fs)
    │       └─ 绑定 --enable-admission-plugins → EnablePlugins
    │
    ├─ cli.Run(command) 
    │   └─ cobra.Execute()  
    │
    ├─ 解析命令行参数  api-server命令行解析发生 cmd.Execute() 内部，在 RunE 回调执行之前
    │   └─ pflag.Parse()
    │       └─ --enable-admission-plugins=NamespaceLifecycle,LimitRanger
    │           └─ 自动写入 opts.Admission.EnablePlugins
    │
    └─ 执行命令逻辑
        └─ RunE 回调函数
            └─ Run(ctx, completedOptions)
                └─ ApplyTo() 读取 opts.Admission.EnablePlugins


 时间线：
  ─────────────────────────────────────────────────→

  NewOptions()     AddFlags()      Execute()        RunE()
      │               │               │                 │
      │               │          pflag.Parse()        │
      │               │          (解析参数)          │
      │               │               │                 │
   创建变量        建立绑定       写入变量          使用变量

  答案：在 cli.Run(command) → cmd.Execute() 内部调用 pflag.Parse() 时解析，此时命令行参数值被写入 opts.Admission.EnablePlugins 等变量。


# 1 获取所有的Admission Plugin放到option结构体的Admission属性

##  所有 Admission Plugins 列表

根据 `pkg/kubeapiserver/options/plugins.go:71-114`，所有可用的 admission plugins 按执行顺序如下：

| Plugin Name | 说明 | 类型 |
|-------------|------|------|
| **AlwaysAdmit** (admit) | 已废弃，总是通过所有请求 | - |
| **NamespaceAutoProvision** | 自动创建不存在的命名空间 | Mutating |
| **NamespaceLifecycle** | 防止删除正在使用的命名空间 | Validating |
| **NamespaceExists** | 确保请求的命名空间存在 | Validating |
| **LimitPodHardAntiAffinityTopology** | 限制 Pod 反亲和性拓扑 | Validating |
| **LimitRanger** | 限制资源使用（CPU/内存等） | Mutating/Validating |
| **ServiceAccount** | 自动为 Pod 挂载 ServiceAccount token | Mutating |
| **NodeRestriction** | 限制节点只修改自身相关的资源 | Validating |
| **TaintNodesByCondition** | 根据节点状态自动设置污点 | Mutating |
| **AlwaysPullImages** | 强制每次拉取镜像，不使用本地缓存 | Mutating |
| **ImagePolicyWebhook** | 镜像策略 webhook 验证 | Validating |
| **PodSecurity** | Pod 安全策略（替代 PSP） | Validating |
| **PodNodeSelector** | 限制 Pod 的节点选择器 | Mutating |
| **Priority** | Pod 优先级和抢占 | Mutating |
| **DefaultTolerationSeconds** | 设置默认的容忍时间 | Mutating |
| **PodTolerationRestriction** | 限制 Pod 的容忍配置 | Mutating/Validating |
| **EventRateLimit** | 事件速率限制 | Validating |
| **ExtendedResourceToleration** | 扩展资源容忍 | Mutating |
| **DefaultStorageClass** | 设置默认 StorageClass | Mutating |
| **StorageObjectInUseProtection** | 防止删除正在使用的 PVC/PV | Mutating |
| **OwnerReferencesPermissionEnforcement** | Owner 引用权限检查 | Validating |
| **PersistentVolumeClaimResize** | PVC 调整大小 | Mutating/Validating |
| **RuntimeClass** | RuntimeClass 配置 | Mutating/Validating |
| **CertificateApproval** | CSR 审批 | Validating |
| **CertificateSigning** | CSR 签名 | Mutating |
| **ClusterTrustBundleAttest** | 集群信任包证明 | Validating |
| **CertificateSubjectRestriction** | CSR 主题限制 | Validating |
| **DefaultIngressClass** | 默认 IngressClass | Mutating |
| **DenyServiceExternalIPs** | 拒绝使用 ExternalIPs 的 Service | Validating |
| **PodTopologyLabels** | Pod 拓扑标签 | Mutating |
| **TenantModeAdmit** | 租户模式 | Validating |
| **CinderAZ** | Cinder 可用区 | Mutating |
| **MutatingAdmissionPolicy** | 变更准入策略 | Mutating |
| **MutatingAdmissionWebhook** | 变更 webhook | Mutating |
| **ValidatingAdmissionPolicy** | 验证准入策略 | Validating |
| **ValidatingAdmissionWebhook** | 验证 webhook | Validating |
| **ResourceQuota** | 资源配额 | Validating |
| **AlwaysDeny** (deny) | 已废弃，总是拒绝所有请求 | - |

---

## 默认启用/禁用的 Plugins

### 默认启用

根据 `plugins.go:161-188`，**默认启用**的有：

```
NamespaceLifecycle, LimitRanger, ServiceAccount, DefaultStorageClass,
PersistentVolumeClaimResize, DefaultTolerationSeconds,
MutatingAdmissionWebhook, ValidatingAdmissionWebhook,
ResourceQuota, StorageObjectInUseProtection, Priority,
TaintNodesByCondition, RuntimeClass, CertificateApproval,
CertificateSigning, ClusterTrustBundleAttest,
CertificateSubjectRestriction, DefaultIngressClass,
PodSecurity, PodTopologyLabels, MutatingAdmissionPolicy,
ValidatingAdmissionPolicy
```

### 默认关闭

```
AlwaysAdmit, NamespaceAutoProvision, NamespaceExists,
LimitPodHardAntiAffinityTopology, NodeRestriction, AlwaysPullImages,
ImagePolicyWebhook, PodNodeSelector, PodTolerationRestriction,
EventRateLimit, ExtendedResourceToleration, OwnerReferencesPermissionEnforcement,
DenyServiceExternalIPs, TenantModeAdmit, CinderAZ, AlwaysDeny
```

---

## apiserver.go NewAPIServerCommand()

## app/options.go NewServerRunOptionos()
获取所有的Admission PLugin 放到option结构体的Admission属性

## kubeapiserver/options/admission.go  NewAdmissionOptions()


## kubeapiserver/options/plugins.go RegisterAllAdmissionPlugins()

    ├─ 创建命令对象（NewOptions() 在这里被调用）
    │   └─ NewAPIServerCommand()
    │       └─ NewServerRunOptions()
    │           └─ NewOptions()
    │               └─ NewAdmissionOptions()
    │                   └─ RegisterAllAdmissionPlugins()  ← 注册插件


│ 2. RegisterAllAdmissionPlugins(options.Plugins)             │
│    // pkg/kubeapiserver/options/plugins.go:124            │
│    ↓                                                        │
│    admit.Register(plugins)                                 │
│    alwayspullimages.Register(plugins)                      │
│    antiaffinity.Register(plugins)                          │
│    ... (30+ plugins)                                       │
│                                                              │
│ 每个 plugin.Register() 做什么？                              │
│    ↓                                                        │
│    plugins.Register(PluginName, pluginFactory)              │
│    // admission.Plugins.Register()                          │
│    ↓                                                        │
│    ps.registry[name] = factory  // 注册到 map                │
└─────────────────────────────────────────────────────────────┘


# 2 Kubernetes Admission Plugins 配置
目的：把option的Admission属性，配置到 server.config的AdmissionControl上（c.AdmissionControl）。

## 内建的Admission Plugin

pkg/kubeapiserver/options/plugins.go
```go
var AllOrderedPlugins = []string{
	admit.PluginName,                        // AlwaysAdmit
	autoprovision.PluginName,                // NamespaceAutoProvision
	lifecycle.PluginName,                    // NamespaceLifecycle
	exists.PluginName,                       // NamespaceExists
	antiaffinity.PluginName,                 // LimitPodHardAntiAffinityTopology
	limitranger.PluginName,                  // LimitRanger
	serviceaccount.PluginName,               // ServiceAccount
	noderestriction.PluginName,              // NodeRestriction
	nodetaint.PluginName,                    // TaintNodesByCondition
	alwayspullimages.PluginName,             // AlwaysPullImages
	imagepolicy.PluginName,                  // ImagePolicyWebhook  镜像拉取相关的plugin
	podsecurity.PluginName,                  // PodSecurity
	podnodeselector.PluginName,              // PodNodeSelector
	podpriority.PluginName,                  // Priority
	defaulttolerationseconds.PluginName,     // DefaultTolerationSeconds
	podtolerationrestriction.PluginName,     // PodTolerationRestriction
	eventratelimit.PluginName,               // EventRateLimit
	extendedresourcetoleration.PluginName,   // ExtendedResourceToleration
	setdefault.PluginName,                   // DefaultStorageClass
	storageobjectinuseprotection.PluginName, // StorageObjectInUseProtection
	gc.PluginName,                           // OwnerReferencesPermissionEnforcement
	resize.PluginName,                       // PersistentVolumeClaimResize
	runtimeclass.PluginName,                 // RuntimeClass
	certapproval.PluginName,                 // CertificateApproval
	certsigning.PluginName,                  // CertificateSigning
	ctbattest.PluginName,                    // ClusterTrustBundleAttest
	certsubjectrestriction.PluginName,       // CertificateSubjectRestriction
	defaultingressclass.PluginName,          // DefaultIngressClass
	denyserviceexternalips.PluginName,       // DenyServiceExternalIPs
	podtopologylabels.PluginName,            // PodTopologyLabels
	tenantmode.PluginName,                   // TenantModeAdmit
	cinderaz.PluginName,                     // CinderAZ

	// new admission plugins should generally be inserted above here
	// webhook, resourcequota, and deny plugins must go at the end

	mutatingadmissionpolicy.PluginName,   // MutatingAdmissionPolicy
	mutatingwebhook.PluginName,           // MutatingAdmissionWebhook    ！！！变更Webhook
	validatingadmissionpolicy.PluginName, // ValidatingAdmissionPolicy
	validatingwebhook.PluginName,         // ValidatingAdmissionWebhook  ！！！ 验证Webhook
	resourcequota.PluginName,             // ResourceQuota
	deny.PluginName,                      // AlwaysDeny
}
```


## apiserger.go main()
CreateKubeAPIServerConfig()

app/server.go buildGenericConfig()


cmd/kube-apiserver/app/server.go
创建核心 **kube API Server config的配置**  用于处理pod、deployment、service等核心资源

```go
// CreateKubeAPIServerConfig creates all the resources for running the API server, but runs none of them
func CreateKubeAPIServerConfig(
	opts options.CompletedOptions,
	genericConfig *genericapiserver.Config,
	versionedInformers clientgoinformers.SharedInformerFactory,
	storageFactory *serverstorage.DefaultStorageFactory,
) (
	*controlplane.Config,
	aggregatorapiserver.ServiceResolver,
	[]admission.PluginInitializer,
	error,
) {
	// global stuff
	capabilities.Setup(opts.AllowPrivileged, opts.MaxConnectionBytesPerSec)

	// additional admission initializers
	// 创建准入控制插件 初始化器
	// 准入控制：拦截API请求，在对象持久化到etcd前进行修改/验证
	// - ValidatingAdmissionWebhook: 调用外部 Webhook 验证
	// - MutatingAdmissionWebhook: 调用外部 Webhook 修改对象
	kubeAdmissionConfig := &kubeapiserveradmission.Config{}
	kubeInitializers, err := kubeAdmissionConfig.New()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create admission plugin initializer: %w", err)
	}

	// 解析 Kubernetes Service 名称到实际后端端点
	serviceResolver, err := buildServiceResolver(opts.EnableAggregatorRouting, genericConfig.LoopbackClientConfig.Host, versionedInformers)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error building service resolver: %w", err)
	}
	// 创建控制平面配置
    // !!!!!! CreateConfig() 添加Admission配置
	controlplaneConfig, admissionInitializers, err := controlplaneapiserver.CreateConfig(opts.CompletedOptions, genericConfig, versionedInformers, storageFactory, serviceResolver, kubeInitializers)
	if err != nil {
		return nil, nil, nil, err
	}

	// 组件核心配置对象
	config := &controlplane.Config{
		ControlPlane: *controlplaneConfig,
		Extra: controlplane.Extra{
			KubeletClientConfig: opts.KubeletConfig,

			ServiceIPRange:          opts.PrimaryServiceClusterIPRange,
			APIServerServiceIP:      opts.APIServerServiceIP,
			SecondaryServiceIPRange: opts.SecondaryServiceClusterIPRange,

			APIServerServicePort: 443,

			ServiceNodePortRange:        opts.ServiceNodePortRange,
			ReserveServiceNodePortRange: opts.ReserveServiceNodePortRange,
			AutoServiceNodePortRange:    opts.AutoServiceNodePortRange,
			KubernetesServiceNodePort:   opts.KubernetesServiceNodePort,

			EndpointReconcilerType: reconcilers.Type(opts.EndpointReconcilerType),
			MasterCount:            opts.MasterCount,
		},
	}



	return config, serviceResolver, admissionInitializers, nil
}


```


pkg/controlplane/apiserver/config.go
```go

func CreateConfig(
	opts options.CompletedOptions,
	genericConfig *genericapiserver.Config,
	versionedInformers clientgoinformers.SharedInformerFactory,
	storageFactory *serverstorage.DefaultStorageFactory,
	serviceResolver aggregatorapiserver.ServiceResolver,
	additionalInitializers []admission.PluginInitializer,
) (
	*Config,
	[]admission.PluginInitializer,
	error,
) {
	proxyTransport := CreateProxyTransport()

	opts.Metrics.Apply()
	serviceaccount.RegisterMetrics()

	config := &Config{
		Generic: genericConfig, // 通用的Config
		Extra: Extra{           // master config中其他的配置
			APIResourceConfigSource: storageFactory.APIResourceConfigSource,
			StorageFactory:          storageFactory,
			EventTTL:                opts.EventTTL,
			EnableLogsSupport:       opts.EnableLogsHandler,
			ProxyTransport:          proxyTransport,
			SystemNamespaces:        opts.SystemNamespaces,

			ServiceAccountIssuer:                opts.ServiceAccountIssuer,
			ServiceAccountMaxExpiration:         opts.ServiceAccountTokenMaxExpiration,
			ServiceAccountExtendedMaxExpiration: opts.Authentication.ServiceAccounts.MaxExtendedExpiration,
			ExtendExpiration:                    opts.Authentication.ServiceAccounts.ExtendExpiration,

			VersionedInformers: versionedInformers,

			CoordinatedLeadershipLeaseDuration: opts.CoordinatedLeadershipLeaseDuration,
			CoordinatedLeadershipRenewDeadline: opts.CoordinatedLeadershipRenewDeadline,
			CoordinatedLeadershipRetryPeriod:   opts.CoordinatedLeadershipRetryPeriod,
		},
	}

    ......



	// setup admission
	// 5 设置Admission 准入控制
	genericAdmissionConfig := controlplaneadmission.Config{
		ExternalInformers:    versionedInformers,
		LoopbackClientConfig: genericConfig.LoopbackClientConfig,
	}
	// 创建通用的admission初始化器
	genericInitializers, err := genericAdmissionConfig.New(proxyTransport, genericConfig.EgressSelector, serviceResolver, genericConfig.TracerProvider)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create admission plugin initializer: %w", err)
	}
	clientgoExternalClient, err := clientgoclientset.NewForConfig(genericConfig.LoopbackClientConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create real client-go external client: %w", err)
	}
	dynamicExternalClient, err := dynamic.NewForConfig(genericConfig.LoopbackClientConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create real dynamic external client: %w", err)
	}
	// 把admission配置到config上
	err = opts.Admission.ApplyTo(
		genericConfig,
		versionedInformers,
		clientgoExternalClient,
		dynamicExternalClient,
		utilfeature.DefaultFeatureGate,
		append(genericInitializers, additionalInitializers...)...,
	)
    ......

	return config, genericInitializers, nil
}
```



pkg/kubeapiserver/options/admission.go

```go

func (a *AdmissionOptions) ApplyTo(
	c *server.Config,
	informers informers.SharedInformerFactory,
	kubeClient kubernetes.Interface,
	dynamicClient dynamic.Interface,
	features featuregate.FeatureGate,
	pluginInitializers ...admission.PluginInitializer,
) error {
	if a == nil {
		return nil
	}

	if a.PluginNames != nil {
		// pass PluginNames to generic AdmissionOptions
		a.GenericAdmission.EnablePlugins, a.GenericAdmission.DisablePlugins = computePluginNames(a.PluginNames, a.GenericAdmission.RecommendedPluginOrder)
	}

	return a.GenericAdmission.ApplyTo(c, informers, kubeClient, dynamicClient, features, pluginInitializers...)
}
```



staging/src/k8s.io/apiserver/pkg/server/options/admission.go
```go

// 构建完整的 admission 插件链并注入到 server 配置中
// a.GenericAdmission.ApplyTo()
func (a *AdmissionOptions) ApplyTo(
	c *server.Config,
	informers informers.SharedInformerFactory,
	kubeClient kubernetes.Interface,
	dynamicClient dynamic.Interface,
	features featuregate.FeatureGate,
	pluginInitializers ...admission.PluginInitializer,
) error {
	if a == nil {
		return nil
	}

	// Admission depends on CoreAPI to set SharedInformerFactory and ClientConfig.
	if informers == nil {
		return fmt.Errorf("admission depends on a Kubernetes core API shared informer, it cannot be nil")
	}
	if kubeClient == nil || dynamicClient == nil {
		return fmt.Errorf("admission depends on a Kubernetes core API client, it cannot be nil")
	}

	// 2. 读取插件配置
	pluginNames := a.enabledPluginNames()

	// 3. 构建初始化器链
	pluginsConfigProvider, err := admission.ReadAdmissionConfiguration(pluginNames, a.ConfigFile, configScheme)
	if err != nil {
		return fmt.Errorf("failed to read plugin config: %v", err)
	}

	discoveryClient := cacheddiscovery.NewMemCacheClient(kubeClient.Discovery())
	discoveryRESTMapper := restmapper.NewDeferredDiscoveryRESTMapper(discoveryClient)
	genericInitializer := initializer.New(kubeClient, dynamicClient, informers, c.Authorization.Authorizer, features,
		c.DrainedNotify(), discoveryRESTMapper)
	initializersChain := admission.PluginInitializers{genericInitializer}
	initializersChain = append(initializersChain, pluginInitializers...)

	admissionPostStartHook := func(hookContext server.PostStartHookContext) error {
		discoveryRESTMapper.Reset()
		go utilwait.Until(discoveryRESTMapper.Reset, 30*time.Second, hookContext.Done())
		return nil
	}

	err = c.AddPostStartHook("start-apiserver-admission-initializer", admissionPostStartHook)
	if err != nil {
		return fmt.Errorf("failed to add post start hook for policy admission: %w", err)
	}
	// 5. 创建 admission chain
	admissionChain, err := a.Plugins.NewFromPlugins(pluginNames, pluginsConfigProvider, initializersChain, a.Decorators)
	if err != nil {
		return err
	}

    // 把所有的Admission PLugin都拿出来，通过传入的参数plugins带出去，最后被交到option的Admission属性上
	c.AdmissionControl = admissionmetrics.WithStepMetrics(admissionChain)
	return nil
}

```

# Admission plugin如何映射到request handler的处理过程中？

installAPIResources：config AdmissionConfig 被放入APIGroupVersion的Admit属性
