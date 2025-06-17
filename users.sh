# Анализ пользователей OEL 9.4 и учетных записей

## Системные пользователи из /etc/passwd

| Пользователь | Категория | Назначение | Связанные сервисы |
|--------------|-----------|------------|-------------------|
| root | Системный | Суперпользователь | Все системы |
| bin, daemon, adm | Системные | Базовые системные службы | Системные утилиты |
| lp | Системный | Печать | CUPS, принтеры |
| sync, shutdown, halt | Системные | Системные операции | Управление питанием |
| mail | Системный | Почтовые службы | Sendmail, Postfix |
| operator, games | Системные | Специализированные роли | Игры, операторские функции |
| ftp | Сетевой | FTP-сервер | FTP-службы |
| nobody | Системный | Безопасный пользователь | Web-сервисы, NFS |
| tss | Безопасность | Trusted Platform Module | TPM, безопасность |
| systemd-coredump | Системный | Core dumps | systemd |
| dbus | Системный | D-Bus message bus | Межпроцессное взаимодействие |
| polkitd | Безопасность | PolicyKit | Авторизация |
| rpc, rpcuser | Сетевой | RPC-службы | NFS, удаленные вызовы |
| sssd | Аутентификация | System Security Services | LDAP, Active Directory |
| sshd | Сетевой | SSH-демон | Удаленный доступ |
| chrony | Системный | Синхронизация времени | NTP |
| systemd-oom | Системный | Out-of-Memory killer | Управление памятью |
| haproxy | Прокси/LB | Load balancer | Балансировка нагрузки |
| tcpdump | Сетевой | Анализ трафика | Мониторинг сети |
| apache | Web-сервер | HTTP-сервер | Web-приложения |
| clevis | Безопасность | Автоматическая расшифровка | LUKS, шифрование |
| clickhouse | База данных | ClickHouse СУБД | Аналитическая БД |
| clickhouse-bridge | База данных | ClickHouse bridge | Интеграция ClickHouse |
| cockpit-ws | Администрирование | Web-интерфейс управления | Cockpit |
| cockpit-wsinstance | Администрирование | Cockpit instances | Cockpit |
| dhcpd | Сетевой | DHCP-сервер | Выдача IP-адресов |
| elasticsearch | Поиск/Аналитика | Elasticsearch | ELK Stack |
| etcd | Кластеризация | Distributed key-value store | Kubernetes, кластеры |
| flatpak | Системный | Приложения Flatpak | Песочница приложений |
| geoclue | Системный | Геолокация | Location services |
| grafana | Мониторинг | Визуализация метрик | Дашборды |
| kafka | Очереди | Message broker | Apache Kafka |
| kibana | Аналитика | Kibana dashboard | ELK Stack |
| libstoragemgmt | Системный | Управление хранилищем | Storage management |
| logstash | Аналитика | Log processing | ELK Stack |
| minio-user | Хранилище | MinIO object storage | S3-совместимое хранилище |
| mon | Мониторинг | Мониторинг (возможно Ceph) | Системы мониторинга |
| mysql | База данных | MySQL/MariaDB | Реляционная БД |
| nginx | Web-сервер | HTTP/reverse proxy | Web-сервисы |
| pipewire | Системный | Аудио/видео сервер | Мультимедиа |
| postgres | База данных | PostgreSQL | Реляционная БД |
| rtkit | Системный | Real-time kit | Аудио real-time |
| setroubleshoot | Безопасность | SELinux troubleshooter | SELinux |
| squid | Прокси | HTTP proxy | Кэширующий прокси |
| telegraf | Мониторинг | Metrics collection | InfluxDB, мониторинг |
| vaudit | Безопасность | Audit (возможно custom) | Аудит безопасности |
| zabbix | Мониторинг | Zabbix agent | Мониторинг инфраструктуры |
| zabbixsrv | Мониторинг | Zabbix server | Сервер мониторинга |

## Дополнительные учетные записи, которые могут существовать

### 1. Учетные записи в базах данных

#### PostgreSQL
```bash
# Просмотр пользователей PostgreSQL
sudo -u postgres psql -c "\du"
sudo -u postgres psql -c "SELECT usename FROM pg_user;"
```

#### MySQL/MariaDB
```bash
# Просмотр пользователей MySQL/MariaDB
mysql -u root -p -e "SELECT User, Host FROM mysql.user;"
```

#### ClickHouse
```bash
# Просмотр пользователей ClickHouse
clickhouse-client --query "SELECT name FROM system.users;"
```

### 2. Системы аутентификации

#### LDAP/Active Directory (через SSSD)
```bash
# Просмотр кэшированных пользователей SSSD
sss_cache -E
getent passwd
id username@domain.com
```

#### Kerberos
```bash
# Просмотр principals
kadmin.local -q "list_principals"
klist -A  # текущие билеты
```

### 3. Контейнеры и виртуализация

#### Docker
```bash
# Пользователи в контейнерах Docker
docker exec container_name cat /etc/passwd
docker exec container_name getent passwd
```

#### Kubernetes (если используется)
```bash
# ServiceAccounts
kubectl get serviceaccounts --all-namespaces
kubectl get clusterrolebindings
kubectl get rolebindings --all-namespaces
```

### 4. Специализированные сервисы

#### HashiCorp Vault
```bash
# Пользователи и политики Vault
vault auth list
vault policy list
vault list auth/userpass/users
```

#### Zabbix
```bash
# Пользователи Zabbix (в БД)
mysql -u zabbix -p zabbix -e "SELECT alias, name FROM users;"
```

#### Grafana
```bash
# Пользователи Grafana (в БД или файлах)
# Обычно в SQLite или PostgreSQL
sqlite3 /var/lib/grafana/grafana.db "SELECT login, email FROM user;"
```

#### MinIO
```bash
# Пользователи MinIO
mc admin user list myminio
```

### 5. Web-приложения и CMS

#### Если есть web-приложения
- WordPress: `wp_users` таблица
- Drupal: `users_field_data` таблица  
- Joomla: `#__users` таблица

### 6. Сетевые сервисы

#### NFS
```bash
# Экспорты NFS
showmount -e localhost
cat /etc/exports
```

#### Samba (если установлен)
```bash
# Пользователи Samba
pdbedit -L
smbpasswd -L
```

### 7. Системы мониторинга

#### Prometheus/AlertManager
```bash
# Конфигурации пользователей
cat /etc/prometheus/web.yml
cat /etc/alertmanager/alertmanager.yml
```

#### ELK Stack
```bash
# Elasticsearch users
curl -X GET "localhost:9200/_security/user"
# Kibana users (обычно через Elasticsearch)
```

## Команды для поиска всех учетных записей

### Системные пользователи
```bash
# Все пользователи системы
getent passwd
cut -d: -f1 /etc/passwd | sort

# Пользователи с shell
grep -v '/nologin\|/false' /etc/passwd

# Группы
getent group
cut -d: -f1 /etc/group | sort
```

### Поиск по конфигурационным файлам
```bash
# Поиск упоминаний пользователей в конфигах
grep -r "user\|username\|login" /etc/ 2>/dev/null | grep -v Binary
find /etc -name "*.conf" -exec grep -l "user\|auth" {} \;
```

### Анализ процессов
```bash
# Пользователи запущенных процессов
ps aux | awk '{print $1}' | sort | uniq
systemctl list-units --type=service --state=active | grep -o '^[^.]*'
```

### Логи аутентификации
```bash
# Анализ логов входа
journalctl -u sshd | grep "Accepted"
last | head -20
who
w
```

### Комплексный аудит
```bash
#!/bin/bash
# Скрипт для поиска всех учетных записей

echo "=== Системные пользователи ==="
getent passwd

echo -e "\n=== Активные сессии ==="
who

echo -e "\n=== Группы ==="
getent group

echo -e "\n=== Sudo пользователи ==="
grep -v '^#' /etc/sudoers /etc/sudoers.d/* 2>/dev/null

echo -e "\n=== Сервисы с пользователями ==="
systemctl list-units --type=service --state=active --no-pager | awk '{print $1}' | while read service; do
    user=$(systemctl show $service -p User --value 2>/dev/null)
    if [ ! -z "$user" ] && [ "$user" != "" ]; then
        echo "$service: $user"
    fi
done
```




















# Анализ учетных записей в кластере Kubernetes на Talos

## Особенности Talos OS

Talos OS - это immutable операционная система, специально созданная для Kubernetes, которая **НЕ имеет**:
- Традиционных пользователей ОС (нет `/etc/passwd`)
- SSH доступа по умолчанию
- Package manager
- Shell доступа

Все управление происходит через API и `talosctl`.

## Учетные записи в Talos Kubernetes кластере

### 1. Системные ServiceAccounts Kubernetes

| ServiceAccount | Namespace | Назначение | Права |
|----------------|-----------|------------|-------|
| default | default, kube-system, etc. | Дефолтный SA для подов | Минимальные |
| kube-proxy | kube-system | Сетевые правила | Управление iptables |
| coredns | kube-system | DNS резолвер | Чтение конфигураций |
| metrics-server | kube-system | Сбор метрик | Чтение метрик подов/нод |
| kube-controller-manager | kube-system | Контроллеры K8s | Управление ресурсами |
| kube-scheduler | kube-system | Планировщик | Назначение подов на ноды |
| etcd | kube-system | Хранилище состояния | Доступ к etcd |
| flannel | kube-system | CNI плагин | Сетевые настройки |

### 2. Talos-специфичные ServiceAccounts

| ServiceAccount | Namespace | Назначение |
|----------------|-----------|------------|
| talos-controller-manager | talos-system | Управление Talos ресурсами |
| machine-controller-manager | machine-system | Управление машинами |
| cluster-autoscaler | kube-system | Автомасштабирование |

### 3. Дополнительные ServiceAccounts (зависят от установленных приложений)

#### Мониторинг
| ServiceAccount | Namespace | Назначение |
|----------------|-----------|------------|
| prometheus | monitoring | Сбор метрик |
| grafana | monitoring | Визуализация |
| alertmanager | monitoring | Алерты |
| node-exporter | monitoring | Метрики нод |
| kube-state-metrics | monitoring | Метрики K8s ресурсов |

#### Логирование
| ServiceAccount | Namespace | Назначение |
|----------------|-----------|------------|
| fluent-bit | logging | Сбор логов |
| elasticsearch | logging | Хранение логов |
| kibana | logging | Поиск по логам |
| logstash | logging | Обработка логов |

#### Ingress и сеть
| ServiceAccount | Namespace | Назначение |
|----------------|-----------|------------|
| nginx-ingress | ingress-nginx | HTTP роутинг |
| traefik | traefik | Reverse proxy |
| cert-manager | cert-manager | Управление TLS сертификатами |
| external-dns | external-dns | Управление DNS записями |

#### Хранилище
| ServiceAccount | Namespace | Назначение |
|----------------|-----------|------------|
| csi-driver | kube-system | Container Storage Interface |
| local-path-provisioner | local-path-storage | Локальное хранилище |
| rook-ceph-operator | rook-ceph | Распределенное хранилище |

#### Безопасность
| ServiceAccount | Namespace | Назначение |
|----------------|-----------|------------|
| vault | vault | Управление секретами |
| external-secrets | external-secrets | Синхронизация внешних секретов |
| falco | falco | Runtime security |
| polaris | polaris | Проверка конфигураций |

### 4. Пользователи в приложениях

#### Базы данных в подах
| Приложение | Пользователи | Где хранятся |
|------------|--------------|--------------|
| PostgreSQL | postgres, app users | ConfigMap, Secret |
| MySQL/MariaDB | root, app users | Secret |
| MongoDB | admin, app users | Secret |
| Redis | default user | Secret (если auth включен) |
| ClickHouse | default, custom users | ConfigMap |

#### Web-приложения
| Тип | Примеры пользователей | Хранилище |
|-----|----------------------|-----------|
| CMS | admin, editors | База данных в поде |
| Auth системы | users, admins | LDAP, база данных |
| CI/CD | jenkins, gitlab users | Внутренние базы |

## Команды для поиска учетных записей

### 1. Talos OS уровень
```bash
# Подключение к Talos API (нет традиционных пользователей)
talosctl -n NODE_IP ps
talosctl -n NODE_IP containers
talosctl -n NODE_IP version

# Нет доступа к /etc/passwd - это immutable OS
```

### 2. Kubernetes ServiceAccounts
```bash
# Все ServiceAccounts во всех namespace
kubectl get serviceaccounts --all-namespaces -o wide

# ServiceAccounts с их секретами
kubectl get serviceaccounts --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.secrets[*].name}{"\n"}{end}'

# ClusterRoleBindings (кто что может делать)
kubectl get clusterrolebindings -o wide

# RoleBindings по namespace
kubectl get rolebindings --all-namespaces -o wide

# Детальная информация о правах
kubectl describe clusterrolebinding system:kube-proxy
kubectl describe rolebinding -n kube-system
```

### 3. Пользователи в подах с базами данных
```bash
# PostgreSQL
kubectl exec -it postgresql-pod -- psql -U postgres -c "\du"

# MySQL/MariaDB  
kubectl exec -it mysql-pod -- mysql -u root -p -e "SELECT User, Host FROM mysql.user;"

# MongoDB
kubectl exec -it mongodb-pod -- mongo admin --eval "db.system.users.find()"

# Redis (если есть auth)
kubectl exec -it redis-pod -- redis-cli AUTH password CONFIG GET requirepass
```

### 4. Secrets и ConfigMaps с учетными данными
```bash
# Все секреты (могут содержать пароли)
kubectl get secrets --all-namespaces

# Детали секретов (base64 encoded)
kubectl get secret mysecret -o jsonpath='{.data}' | base64 -d

# ConfigMaps с возможными учетными данными
kubectl get configmaps --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}' | grep -E "(user|auth|login|passwd)"
```

### 5. Анализ RBAC
```bash
# Кто имеет cluster-admin права
kubectl get clusterrolebindings -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.metadata.name}{"\t"}{.subjects[*].name}{"\n"}{end}'

# Все роли и их права
kubectl get clusterroles -o name | xargs -I {} kubectl describe {}

# ServiceAccounts с токенами
kubectl get serviceaccounts --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.secrets[*].name}{"\n"}{end}' | grep -v "^$"
```

### 6. Поиск в логах
```bash
# Аутентификация в API server
kubectl logs -n kube-system kube-apiserver-* | grep -i "auth\|login\|user"

# Audit логи (если включены)
talosctl -n NODE_IP logs kubernetes-audit

# Логи подов с возможными аuth событиями
kubectl logs -l app=auth-app | grep -i "login\|user\|auth"
```

### 7. Внешние системы аутентификации
```bash
# OIDC провайдеры (в kube-apiserver конфиге)
talosctl -n NODE_IP get machineconfig -o jsonpath='{.spec.cluster.apiServer.oidcIssuerURL}'

# LDAP интеграции (в приложениях)
kubectl get configmaps --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.data}{"\n"}{end}' | grep -i ldap

# External secrets операторы
kubectl get externalsecrets --all-namespaces
kubectl get secretstores --all-namespaces
```

## Комплексный скрипт аудита

```bash
#!/bin/bash
# Аудит учетных записей в Talos Kubernetes

echo "=== Talos Cluster Info ==="
talosctl version
kubectl cluster-info

echo -e "\n=== All ServiceAccounts ==="
kubectl get serviceaccounts --all-namespaces

echo -e "\n=== ClusterRoleBindings ==="
kubectl get clusterrolebindings -o wide

echo -e "\n=== Secrets (potential credentials) ==="
kubectl get secrets --all-namespaces | grep -v "token-"

echo -e "\n=== Users with cluster-admin ==="
kubectl get clusterrolebindings -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.metadata.name}{": "}{.subjects[*].name}{"\n"}{end}'

echo -e "\n=== Database pods ==="
kubectl get pods --all-namespaces -l app=postgresql -o wide
kubectl get pods --all-namespaces -l app=mysql -o wide
kubectl get pods --all-namespaces -l app=mongodb -o wide

echo -e "\n=== ConfigMaps with potential auth data ==="
kubectl get configmaps --all-namespaces -o name | xargs kubectl describe | grep -i -A5 -B5 "user\|password\|auth\|login"
```

## Специфичные места поиска в Talos

### 1. Machine Config
```bash
# Конфигурация аутентификации кластера
talosctl -n NODE_IP get machineconfig -o yaml | grep -A10 -B10 -i "auth\|user"
```

### 2. Kubernetes конфигурации
```bash
# API Server auth настройки
kubectl -n kube-system get pod kube-apiserver-* -o yaml | grep -i "oidc\|webhook\|token"
```

### 3. Helm releases
```bash
# Если используется Helm
helm list --all-namespaces
helm get values release-name -n namespace
```

**Важно**: В Talos нет традиционных OS пользователей - все учетные записи существуют только в контексте Kubernetes и приложений, запущенных в подах.
