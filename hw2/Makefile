# indicating that target "all" and "clean" are not files
.PHONY: all clean

# set some variables
CC = gcc
CFLAGS = -Wall -Wextra -Werror -O3 -pthread
OUTPUT_OPTION = -MMD -MP -o $@

SOURCE = sched_demo_main.c sched_demo_worker.c
OBJS = $(SOURCE:.c=.o)
DEPS = $(SOURCE:.c=.d)
HEADERS = sched_demo.h
TARGET = sched_demo_313551003

# first command of make
all: $(TARGET)

# import the dependencies of .h .c files from the compiler
-include $(DEPS)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< $(OUTPUT_OPTION)

# clean the target, object files, and dependency files
clean:
	@rm -f $(TARGET) $(OBJS) $(DEPS)
