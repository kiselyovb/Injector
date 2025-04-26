Тестирование

Разовая загрузка без проверки подписей
	Нажми Win + R → введи
		shutdown /r /o /f /t 0
	После перезагрузки выбери: Поиск и устранение неисправностей
		→ Дополнительные параметры
		→ Параметры загрузки
		→ Перезагрузить
	После второй перезагрузки:
		Нажми клавишу 7 или F7 —Отключить обязательную проверку подписи драйверов
Постоянное отключение, запуск cmd.exe от имени администратора
	Выключить:
		bcdedit /set nointegritychecks on
		bcdedit /set testsigning on
	Включить:
		bcdedit /set nointegritychecks off
		bcdedit /set testsigning off


"D:\DragBlock\Injector.exe" /all Notepad "D:\DragBlock\DragBlock.dll" /gui
eventvwr.msc
