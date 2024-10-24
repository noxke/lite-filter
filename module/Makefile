MODULE_NAME=lite_filter
PWD=$(shell pwd)
KDIR := /lib/modules/$(shell uname -r)/build

# make -C之后识别源文件位置
ifdef M
	SRC_DIR := $(M)/src
	INC_DIR := $(M)/include
	EXTRA_CFLAGS += -I$(INC_DIR)
	SRCS := $(wildcard $(SRC_DIR)/*.c)
	OBJS := $(SRCS:$(M)/%.c=%.o)
endif

$(MODULE_NAME)-objs := $(OBJS)
obj-m += $(MODULE_NAME).o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	insmod $(MODULE_NAME).ko

uninstall:
	rmmod $(MODULE_NAME)

test:
	insmod $(MODULE_NAME).ko
	rmmod $(MODULE_NAME)
	insmod $(MODULE_NAME).ko
	rmmod $(MODULE_NAME)
	insmod $(MODULE_NAME).ko
	rmmod $(MODULE_NAME)
	dmesg

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean