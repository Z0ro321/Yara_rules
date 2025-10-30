# YARA Rules for Process Monitor Detection

Набор кастомных YARA правил для детектирования монитора процессов по различным характеристикам. Каждое правило использует уникальный подход к обнаружению, обеспечивая многоуровневый анализ.

## Правила детектирования

- **ProcessMonitor_String** - обнаружение по уникальным строковым константам
- **ProcessMonitor_Hex** - сигнатура по magic number и ELF заголовку  
- **ProcessMonitor_Size** - детектирование по точному размеру файла
- **ProcessMonitor_Hash** - идентификация по характерным функциям
- **ProcessMonitor_XOR** - анализ по именам секций исполняемого файла

## Использование
```bash
yara process_monitor_rules.yar target_file
