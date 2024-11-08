SRCS := $(notdir $(wildcard src/*.c))
OBJS := $(patsubst %.c, %.o, $(SRCS))

INC := include

TARGET := lite-filter

default: $(TARGET)

$(TARGET):$(OBJS)
	gcc -o $@ $^

%.o: src/%.c
	gcc -o2 -c -std=c17 -o $@ $< -I$(INC)

.PHONY :clean
clean:
	rm $(OBJS) $(TARGET)