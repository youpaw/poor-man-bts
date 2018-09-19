
KDIR ?= /lib/modules/$(shell uname -r)/build

module:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean


#addr := ffffffffb5243454
#addr := ffffffffb5243478
#addr := ffffffffb5452e73
#addr := ffffffff97a52e73
#len := 2

try: module
	sudo rmmod poormanbts || :
	sudo insmod ./poormanbts.ko
	echo "0x$(addr)+0x$(len)" | sudo tee /proc/poormanbts
	sudo head -n 20 /proc/poormanbts
