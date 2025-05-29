#!/bin/bash

echo "Устройство;Параметр;Значение"

# Получение списка устройств без loop и ram
devices=$(lsblk -ndo NAME,TYPE | awk '$2=="disk" {print "/dev/"$1}')

for device in $devices; do
    # Модель диска
    model=$(cat /sys/block/$(basename "$device")/device/model 2>/dev/null)
    if [[ -n "$model" ]]; then
        echo "$device;Модель диска;$model"
    else
        model=$(udevadm info --query=all --name=$device | grep ID_MODEL= | cut -d= -f2-)
        if [[ -n "$model" ]]; then
            echo "$device;Модель диска;$model"
        fi
    fi

    # Размер диска (в GiB)
    size_line=$(fdisk -l $device 2>/dev/null | grep -m1 -E "^Disk $device:")

    if [[ -z "$size_line" ]]; then
        size_line=$(fdisk -l 2>/dev/null | grep -m1 -E "^Disk $device:")
    fi

    if [[ -n "$size_line" ]]; then
        size=$(echo "$size_line" | cut -d: -f2 | cut -d',' -f1 | xargs)
        echo "$device;Размер диска;$size"
    fi

    # Размер сектора
    sector_line=$(fdisk -l $device 2>/dev/null | grep "Sector size" | head -n1)
    if [[ -n "$sector_line" ]]; then
        sectors=$(echo "$sector_line" | sed -E 's/.*logical\/physical: ([^ ]+ [^,]+).*/\1/')
        echo "$device;Размер сектора (лог/физ);$sectors"
    fi

    # Размер I/O
    io_size=$(cat /sys/block/$(basename "$device")/queue/logical_block_size 2>/dev/null)
    if [[ -n "$io_size" ]]; then
        echo "$device;Размер I/O (мин/опт);${io_size} байт / ${io_size} байт"
    fi

    # Тип метки диска
    label=$(parted -s $device print 2>/dev/null | grep "Partition Table" | awk -F: '{print $2}' | xargs)
    if [[ -n "$label" ]]; then
        echo "$device;Тип метки диска;$label"
    fi

    # Идентификатор диска
    disk_id=$(fdisk -l $device 2>/dev/null | grep "Disk identifier" | awk -F: '{print $2}' | xargs)
    if [[ -n "$disk_id" ]]; then
        echo "$device;Идентификатор диска;$disk_id"
    fi

    # Разделы
    partitions=$(lsblk -ln $device | awk '$1 ~ /^[^ ]+p[0-9]+/ {print $1, $4}')
    while IFS= read -r part; do
        part_name=$(echo "$part" | awk '{print $1}')
        part_size=$(echo "$part" | awk '{print $2}')
        echo "$device;Раздел /dev/$part_name;Размер $part_size"
    done <<< "$partitions"
done
