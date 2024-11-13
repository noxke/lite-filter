APP := ./app/lite-filter
MODULE := ./module/lite_filter.ko

default: $(APP) $(MODULE)

$(APP):
	make -C app

$(MODULE):
	make -C module

.PHONY :clean install uninstall
clean:
	make -C app clean
	make -C module clean

install:
	mkdir -p /etc/lite-filter
	mkdir -p /usr/lib/lite-filter
	mkdir -p /tmp/lite-filter
	cp $(APP) /usr/bin/
	chmod +x /usr/bin/lite-filter
	cp $(MODULE) /usr/lib/lite-filter/
	cp ./configs/lite-filter.conf /etc/lite-filter/
	cp ./configs/lite-filter.rule /etc/lite-filter/

uninstall:
	rm -rf /etc/lite-filter
	rm -rf /usr/lib/lite-filter
	rm -rf /tmp/lite-filter
	rm -f /usr/bin/lite-filter
