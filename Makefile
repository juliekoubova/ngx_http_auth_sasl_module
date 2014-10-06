default:	build

NGINX_ROOT = ../nginx
PFCONF     = /etc/pf.conf

.PHONY: clean configure build start stop

clean:
	if [ -e $(NGINX_ROOT)/Makefile ]; then \
		$(MAKE) -C $(NGINX_ROOT) clean;    \
	fi
	rm -rf root nginx.core

configure: stop
	cd $(NGINX_ROOT) && ./configure --with-debug \
		                            --add-module=${.CURDIR}/src

build: stop
	$(MAKE) -C $(NGINX_ROOT) build

root:
	mkdir -p root/logs

root/debug.conf: root debug.conf
	cp ${.CURDIR}/debug.conf root/debug.conf

root/logs: root
	mkdir -p root/logs

start:	build root/logs root/debug.conf
	rm -f root/logs/error.log
	cat $(PFCONF) ${.CURDIR}/pf.start | sudo pfctl -f -
	$(NGINX_ROOT)/objs/nginx -p ${.CURDIR}/root -c debug.conf

stop:
	if [ -e ${.CURDIR}/root/logs/nginx.pid ]; then \
		if [ -x $(NGINX_ROOT)/objs/nginx ]; then \
			$(NGINX_ROOT)/objs/nginx -s stop -p ${.CURDIR}/root -c debug.conf; \
		fi ; \
		sudo pfctl -f $(PFCONF); \
	fi
