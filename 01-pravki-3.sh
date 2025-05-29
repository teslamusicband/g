#!/bin/bash

# Список серверов для аудита (скопирован из audit2.sh)
SERVERS=(
    "192.168.72.4:service"
    "192.168.72.5:service"
    "192.168.72.6:service"
    "192.168.72.7:service"
)

# Директория с результатами аудита
AUDIT_DIR=${1:-"server_audit_$(date +%Y%m%d)"}

# Функция для извлечения IP адресов серверов
get_server_ips() {
    local server_ips=()
    for server_info in "${SERVERS[@]}"; do
        local server_ip=$(echo "$server_info" | cut -d: -f1)
        server_ips+=("$server_ip")
    done
    echo "${server_ips[@]}"
}

# Функция для создания заголовка таблицы
create_header() {
    local server_ips=($(get_server_ips))
    local header="Раздел элемента аудита;Имя файла вывода;Команда;Род вывода;Вид части вывода"

    for server_ip in "${server_ips[@]}"; do
        header="$header;$server_ip"
    done

    echo "$header"
}

# Функция для преобразования данных одного сервера
parse_server_data() {
    local server_ip="$1"
    local input_file="$AUDIT_DIR/$server_ip/01_system_info.txt"

    # Массив для хранения данных сервера
    declare -A server_data

    if [[ -f "$input_file" ]]; then
        local line_number=1
        while IFS= read -r line; do
            # Пропускаем пустые строки
            [[ -z "$line" ]] && { ((line_number++)); continue; }

            case $line_number in
                1)
                    # Первая строка - hostname
                    server_data["hostname"]="$line"
                    ;;
                2)
                    # Вторая строка - uname -a (разбираем на компоненты)
                    local uname_parts=($line)
                    server_data["os_name"]="${uname_parts[0]}"
                    server_data["kernel_version"]="${uname_parts[2]}"
                    # Извлекаем архитектуру и убираем .x86_64 из версии ядра если есть
                    local arch="${uname_parts[10]}"
                    if [[ "${server_data["kernel_version"]}" == *".x86_64" ]]; then
                        server_data["kernel_version"]="${server_data["kernel_version"]%%.x86_64}"
                        arch="x86_64"
                    fi
                    server_data["architecture"]="$arch"
                    ;;
                3)
                    # Третья строка - версия дистрибутива
                    server_data["distrib_version"]="$line"
                    ;;
            esac
            ((line_number++))
        done < "$input_file"
    else
        # Если файл не найден, заполняем пустыми значениями
        server_data["hostname"]="N/A"
        server_data["os_name"]="N/A"
        server_data["kernel_version"]="N/A"
        server_data["architecture"]="N/A"
        server_data["distrib_version"]="N/A"
    fi

    # Возвращаем данные в виде строки, разделенной символами |
    echo "${server_data[hostname]}|${server_data[os_name]}|${server_data[kernel_version]}|${server_data[architecture]}|${server_data[distrib_version]}"
}

# Функция для создания строки таблицы
create_table_row() {
    local row_type="$1"
    local command="$2"
    local category="$3"
    local parameter="$4"
    local server_ips=($(get_server_ips))

    local row="Базовая информация о системе;01_system_info.txt;$command;$category;$parameter"

    # Собираем данные со всех серверов
    for server_ip in "${server_ips[@]}"; do
        local server_data=$(parse_server_data "$server_ip")
        # Используем IFS для правильного разделения по символу |
        IFS='|' read -r hostname os_name kernel_version architecture distrib_version <<< "$server_data"

        case $row_type in
            "hostname")
                row="$row;$hostname"
                ;;
            "os_name")
                row="$row;$os_name"
                ;;
            "kernel_version")
                row="$row;$kernel_version"
                ;;
            "architecture")
                row="$row;$architecture"
                ;;
            "distrib_version")
                row="$row;$distrib_version"
                ;;
        esac
    done

    echo "$row"
}

# Основная функция для создания таблицы
create_system_info_table() {
    # Выводим заголовок
    create_header

    # Выводим только корректные строки (зелёные из скриншота)
    create_table_row "hostname" "hostname" "Системная идентификация" "Имя хоста"
    create_table_row "os_name" "uname -a" "Системная информация" "Операционная система"
    create_table_row "kernel_version" "uname -a" "Системная информация" "Версия ядра"
    create_table_row "architecture" "uname -a" "Системная информация" "Архитектура"
    create_table_row "distrib_version" "cat /etc/oracle-release" "Дистрибутив" "Версия дистрибутива"
}

# Основная логика скрипта
main() {
    if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        echo "Использование: $0 [директория_аудита]"
        echo "Преобразует данные из файлов 01_system_info.txt всех серверов в единую таблицу"
        echo "Формат вывода: таблица с разделителями ;"
        echo ""
        echo "Примеры:"
        echo "  $0                           # Использовать server_audit_YYYYMMDD"
        echo "  $0 server_audit_20241201     # Использовать указанную директорию"
        exit 0
    fi

    # Проверяем существование директории аудита
    if [[ ! -d "$AUDIT_DIR" ]]; then
        echo "Ошибка: директория аудита '$AUDIT_DIR' не найдена" >&2
        echo "Убедитесь, что скрипт audit2.sh был выполнен" >&2
        exit 1
    fi

    # Создаем таблицу
    create_system_info_table
}

# Запускаем основную функцию
main "$@"
