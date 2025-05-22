#!/bin/bash

# SSH Key Distribution Script for OEL 9.4 Server Group
# Автоматическая генерация и распространение SSH ключей для user1 на всей группе серверов

set -euo pipefail

# Конфигурация
USERNAME="user1"
PASSWORD="user1"
KEY_TYPE="rsa"
KEY_SIZE="4096"
KEY_COMMENT="user1@cluster-$(date +%Y%m%d)"

# Список серверов (замените на ваши IP адреса)
SERVERS=(
    "192.168.1.10"
    "192.168.1.11"
    "192.168.1.12"
    "192.168.1.13"
    "192.168.1.14"
    "192.168.1.15"
    "192.168.1.16"
    "192.168.1.17"
    "192.168.1.18"
    "192.168.1.19"
    "192.168.1.20"
    "192.168.1.21"
    "192.168.1.22"
    "192.168.1.23"
    "192.168.1.24"
)

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функции логирования
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" >&2
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

# Проверка зависимостей
check_dependencies() {
    log "Проверка зависимостей..."
    
    local deps=("ssh" "sshpass")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        error "Отсутствуют зависимости: ${missing_deps[*]}"
        log "Установка зависимостей..."
        
        # Определение пакетного менеджера
        if command -v dnf &> /dev/null; then
            sudo dnf install -y openssh-clients sshpass
        elif command -v yum &> /dev/null; then
            sudo yum install -y openssh-clients sshpass
        else
            error "Не удалось найти пакетный менеджер (dnf/yum)"
            exit 1
        fi
    fi
    
    success "Все зависимости установлены"
}

# Проверка доступности сервера
check_server_connectivity() {
    local server="$1"
    local timeout=5
    
    # Проверка ping
    if ! ping -c 1 -W "$timeout" "$server" &> /dev/null; then
        return 1
    fi
    
    # Проверка SSH порта
    if ! timeout "$timeout" bash -c "</dev/tcp/$server/22" 2>/dev/null; then
        return 1
    fi
    
    return 0
}

# Выполнение команды на удаленном сервере
execute_remote_command() {
    local server="$1"
    local command="$2"
    local timeout="${3:-30}"
    
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout="$timeout" -o ServerAliveInterval=10 "$USERNAME@$server" "$command"
}

# Генерация SSH ключей на удаленном сервере
generate_keys_on_server() {
    local server="$1"
    
    log "Генерация SSH ключей на сервере $server..."
    
    local remote_commands="
        # Создание .ssh директории
        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        
        # Проверка существования ключей
        if [[ -f ~/.ssh/id_rsa ]]; then
            echo 'EXISTING_KEY_FOUND'
        else
            # Генерация новой пары ключей
            ssh-keygen -t $KEY_TYPE -b $KEY_SIZE -C '$KEY_COMMENT' -f ~/.ssh/id_rsa -N ''
            chmod 600 ~/.ssh/id_rsa
            chmod 644 ~/.ssh/id_rsa.pub
            echo 'NEW_KEY_GENERATED'
        fi
        
        # Вывод публичного ключа
        echo 'PUBLIC_KEY_START'
        cat ~/.ssh/id_rsa.pub
        echo 'PUBLIC_KEY_END'
    "
    
    if execute_remote_command "$server" "$remote_commands"; then
        success "SSH ключи готовы на $server"
        return 0
    else
        error "Ошибка генерации ключей на $server"
        return 1
    fi
}

# Получение публичного ключа с сервера
get_public_key_from_server() {
    local server="$1"
    
    # Выполняем команду и возвращаем только результат, подавляя логи
    execute_remote_command "$server" "cat ~/.ssh/id_rsa.pub 2>/dev/null || echo 'NO_KEY_FOUND'" 2>/dev/null
}

# Добавление публичного ключа в authorized_keys на сервере
add_key_to_authorized_keys() {
    local server="$1"
    local public_key="$2"
    
    # Экранируем ключ для безопасной передачи
    local escaped_key=$(printf '%q' "$public_key")
    
    # Создаем временный файл на удаленном сервере для безопасной передачи ключа
    local remote_commands="
        # Создание .ssh директории если не существует
        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        
        # Создание authorized_keys если не существует
        touch ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
        
        # Создаем временный файл с ключом
        TEMP_KEY_FILE=\$(mktemp)
        echo $escaped_key > \"\$TEMP_KEY_FILE\"
        
        # Проверка, существует ли уже этот ключ
        if ! grep -qxF \"\$(cat \"\$TEMP_KEY_FILE\")\" ~/.ssh/authorized_keys 2>/dev/null; then
            cat \"\$TEMP_KEY_FILE\" >> ~/.ssh/authorized_keys
            echo 'KEY_ADDED'
        else
            echo 'KEY_EXISTS'
        fi
        
        # Удаляем временный файл
        rm -f \"\$TEMP_KEY_FILE\"
        
        # Настройка SELinux контекста для OEL
        if command -v restorecon &> /dev/null; then
            restorecon -R ~/.ssh/
        fi
    "
    
    execute_remote_command "$server" "$remote_commands"
}

# Проверка всех серверов
check_all_servers() {
    log "Проверка доступности всех серверов..."
    
    local available_servers=()
    local unavailable_servers=()
    
    for server in "${SERVERS[@]}"; do
        if check_server_connectivity "$server"; then
            available_servers+=("$server")
            success "Сервер доступен: $server"
        else
            unavailable_servers+=("$server")
            error "Сервер недоступен: $server"
        fi
    done
    
    if [ ${#unavailable_servers[@]} -gt 0 ]; then
        error "Недоступные серверы: ${unavailable_servers[*]}"
        read -p "Продолжить с доступными серверами? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Обновляем список серверов, оставляя только доступные
    SERVERS=("${available_servers[@]}")
    log "Работаем с ${#SERVERS[@]} доступными серверами"
}

# Генерация ключей на всех серверах
generate_all_keys() {
    log "Генерация SSH ключей на всех серверах..."
    
    local failed_servers=()
    
    for server in "${SERVERS[@]}"; do
        if ! generate_keys_on_server "$server"; then
            failed_servers+=("$server")
        fi
        echo "----------------------------------------"
    done
    
    if [ ${#failed_servers[@]} -gt 0 ]; then
        error "Не удалось сгенерировать ключи на серверах: ${failed_servers[*]}"
        return 1
    fi
    
    success "SSH ключи сгенерированы на всех серверах"
}

# Сбор всех публичных ключей
collect_public_keys() {
    log "Сбор публичных ключей со всех серверов..."
    
    # Используем короткое предсказуемое имя файла
    local temp_keys_file="/tmp/ssh_keys_$(date +%s).txt"
    local failed_servers=()
    
    # Убеждаемся, что файл не существует
    rm -f "$temp_keys_file"
    touch "$temp_keys_file"
    
    for server in "${SERVERS[@]}"; do
        log "Получение публичного ключа с $server..."
        
        # Получаем ключ, подавляя вывод в stdout
        local public_key
        public_key=$(get_public_key_from_server "$server" 2>/dev/null)
        
        if [[ "$public_key" != "NO_KEY_FOUND" && -n "$public_key" ]]; then
            echo "$public_key" >> "$temp_keys_file"
            success "Ключ получен с $server"
        else
            error "Не удалось получить ключ с $server"
            failed_servers+=("$server")
        fi
    done
    
    if [ ${#failed_servers[@]} -gt 0 ]; then
        warning "Не удалось получить ключи с серверов: ${failed_servers[*]}"
    fi
    
    local keys_count=$(wc -l < "$temp_keys_file")
    log "Собрано $keys_count публичных ключей"
    
    # Возвращаем только имя файла в stdout
    echo "$temp_keys_file"
}

# Распространение ключей на все серверы
distribute_keys() {
    local keys_file="$1"
    
    log "Распространение всех публичных ключей на все серверы..."
    
    local successful_distributions=0
    local failed_distributions=0
    local line_number=0
    
    # Читаем файл построчно, избегая длинных аргументов командной строки
    while IFS= read -r public_key || [[ -n "$public_key" ]]; do
        # Пропускаем пустые строки
        [[ -z "$public_key" ]] && continue
        
        # Безопасное увеличение счетчика
        line_number=$((line_number + 1))
        
        # Показываем только первые 50 символов ключа для читаемости
        local key_preview="${public_key:0:50}"
        log "Распространение ключа #$line_number: ${key_preview}..."
        
        for server in "${SERVERS[@]}"; do
            log "  -> Добавление на $server"
            
            if result=$(add_key_to_authorized_keys "$server" "$public_key"); then
                if [[ "$result" == *"KEY_ADDED"* ]]; then
                    success "    Ключ добавлен на $server"
                    successful_distributions=$((successful_distributions + 1))
                elif [[ "$result" == *"KEY_EXISTS"* ]]; then
                    log "    Ключ уже существует на $server"
                fi
            else
                error "    Ошибка добавления ключа на $server"
                failed_distributions=$((failed_distributions + 1))
            fi
        done
        echo "----------------------------------------"
    done < "$keys_file"
    
    log "Распространение ключей завершено"
    log "Успешных операций: $successful_distributions"
    log "Неудачных операций: $failed_distributions"
}

# Тестирование SSH соединений между серверами
test_cross_connections() {
    log "Тестирование SSH соединений между серверами..."
    
    local total_tests=0
    local successful_tests=0
    # Используем короткое предсказуемое имя файла
    local test_results_file="/tmp/ssh_test_$(date +%s).txt"
    
    # Убеждаемся, что файл не существует
    rm -f "$test_results_file"
    touch "$test_results_file"
    
    for source_server in "${SERVERS[@]}"; do
        for target_server in "${SERVERS[@]}"; do
            # Пропускаем соединение сервера с самим собой
            [[ "$source_server" == "$target_server" ]] && continue
            
            # Безопасное увеличение счетчика
            total_tests=$((total_tests + 1))
            
            log "Тест: $source_server -> $target_server"
            
            # Команда для тестирования SSH соединения
            local test_command="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes $USERNAME@$target_server 'echo \"Connection from \$(hostname) to \$(hostname)\" && whoami' 2>/dev/null"
            
            if execute_remote_command "$source_server" "$test_command" >/dev/null 2>&1; then
                success "$source_server -> $target_server: OK"
                echo "$source_server -> $target_server: SUCCESS" >> "$test_results_file"
                successful_tests=$((successful_tests + 1))
            else
                error "$source_server -> $target_server: FAILED"
                echo "$source_server -> $target_server: FAILED" >> "$test_results_file"
            fi
        done
    done
    
    log "Результаты тестирования SSH соединений:"
    log "Всего тестов: $total_tests"
    log "Успешных: $successful_tests"
    log "Неудачных: $((total_tests - successful_tests))"
    
    if [ $successful_tests -eq $total_tests ]; then
        success "Все SSH соединения работают корректно!"
    else
        warning "Некоторые SSH соединения не работают. Проверьте логи."
    fi
    
    echo "$test_results_file"
}

# Генерация итогового отчета
generate_final_report() {
    local test_results_file="$1"
    local report_file="ssh_cluster_deployment_report_$(date +%Y%m%d_%H%M%S).txt"
    
    log "Генерация итогового отчета: $report_file"
    
    {
        echo "SSH Cluster Key Deployment Report"
        echo "================================="
        echo "Date: $(date)"
        echo "User: $USERNAME"
        echo "Key Type: $KEY_TYPE ($KEY_SIZE bits)"
        echo "Total Servers: ${#SERVERS[@]}"
        echo ""
        echo "Server List:"
        printf '%s\n' "${SERVERS[@]}"
        echo ""
        echo "Cross-Connection Test Results:"
        echo "------------------------------"
        if [[ -f "$test_results_file" ]]; then
            cat "$test_results_file"
        else
            echo "No test results available"
        fi
        echo ""
        echo "Deployment completed at: $(date)"
        echo ""
        echo "Usage:"
        echo "Now you can SSH from any server to any other server in the cluster:"
        echo "ssh $USERNAME@<target_server_ip>"
    } > "$report_file"
    
    success "Отчет сохранен: $report_file"
}

# Очистка временных файлов
cleanup() {
    log "Очистка временных файлов..."
    # Удаляем временные файлы с предсказуемыми именами
    rm -f /tmp/ssh_keys_*.txt 2>/dev/null || true
    rm -f /tmp/ssh_test_*.txt 2>/dev/null || true
}

# Основная функция
main() {
    log "Начало настройки SSH ключей для кластера серверов OEL 9.4"
    log "Пользователь: $USERNAME"
    log "Исходное количество серверов: ${#SERVERS[@]}"
    
    # Проверка зависимостей
    check_dependencies
    
    # Проверка доступности всех серверов
    check_all_servers
    
    if [ ${#SERVERS[@]} -eq 0 ]; then
        error "Нет доступных серверов для работы"
        exit 1
    fi
    
    # Генерация ключей на всех серверах
    generate_all_keys
    
    # Сбор всех публичных ключей
    local keys_file=$(collect_public_keys)
    
    # Распространение ключей на все серверы
    distribute_keys "$keys_file"
    
    # Тестирование соединений между серверами
    local test_results_file=$(test_cross_connections)
    
    # Генерация итогового отчета
    generate_final_report "$test_results_file"
    
    # Очистка
    cleanup
    rm -f "$keys_file" "$test_results_file"
    
    success "Настройка SSH кластера завершена!"
    log "Теперь с любого сервера можно подключиться к любому другому:"
    log "ssh $USERNAME@<target_server_ip>"
}

# Обработка сигналов
trap 'echo ""; error "Прервано пользователем"; cleanup; exit 1' INT TERM

# Проверка, что скрипт не запущен от root
if [[ $EUID -eq 0 ]]; then
    error "Не запускайте этот скрипт от пользователя root"
    exit 1
fi

# Запуск основной функции
main "$@"
