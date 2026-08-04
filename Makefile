# Makefile for SupportProxy

# Compiler settings
CXX ?= g++
CXXFLAGS := -O2 -Wall -g -Werror -Wextra -Werror=format -Wpointer-arith -Wcast-align -Wno-missing-field-initializers -Wno-unused-parameter -Wno-redundant-decls
CXXFLAGS := $(CXXFLAGS) -Wno-unknown-pragmas -Wno-trigraphs -Werror=shadow -Werror=return-type -Werror=unused-result -Werror=unused-variable -Werror=narrowing
CXXFLAGS := $(CXXFLAGS) -Werror=attributes -Werror=overflow -Werror=parentheses -Werror=format-extra-args -Werror=ignored-qualifiers -Werror=undef
# longer signing time window
CXXFLAGS := $(CXXFLAGS) -DMAVLINK_SIGNING_TIMESTAMP_LIMIT=600

# Library settings
LIBS := -ltdb -lssl -lcrypto

# Source files
SOURCES := supportproxy.cpp mavlink.cpp util.cpp keydb.cpp conntdb.cpp tlog.cpp session.cpp binlog.cpp cleanup.cpp websocket.cpp video.cpp videoauth.cpp videots.cpp videostream.cpp videorec.cpp videoview.cpp httpreq.cpp videortsp.cpp videortmp.cpp
OBJECTS := $(SOURCES:.cpp=.o)
TARGET := supportproxy

# Build directories
BUILD_DIR := build
MAVLINK_DIR := libraries/mavlink2/generated

.PHONY: all clean distclean headers modules help test

# Default target
all: modules headers $(TARGET)

# Help target
help:
	@echo "SupportProxy Build System"
	@echo "====================="
	@echo "Available targets:"
	@echo "  all       - Build everything (default)"
	@echo "  headers   - Generate MAVLink headers"
	@echo "  modules   - Initialize git submodules"
	@echo "  clean     - Remove build artifacts"
	@echo "  distclean - Remove all generated files"
	@echo "  test      - Run basic tests"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Environment variables:"
	@echo "  CXX       - C++ compiler (default: g++)"

# Git submodules
modules: modules/mavlink/message_definitions/v1.0/all.xml

modules/mavlink/message_definitions/v1.0/all.xml:
	@echo "Initializing git submodules..."
	@git submodule update --init --recursive

# MAVLink headers generation
headers: $(MAVLINK_DIR)/protocol.h

$(MAVLINK_DIR)/protocol.h: modules/mavlink/message_definitions/v1.0/all.xml
	@echo "Generating MAVLink headers..."
	@./regen_headers.sh

# Main target
$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

# Object file compilation
%.o: %.cpp
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Special rule for mavlink.o to suppress stringop-truncation warning
# This is needed due to MAVLink library using strncpy for fixed-size character arrays
mavlink.o: mavlink.cpp mavlink.h $(MAVLINK_DIR)/protocol.h
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) -Wno-stringop-truncation -c $< -o $@

# Dependencies. mavlink.h includes keydb.h, so any object that pulls in
# mavlink.h transitively depends on keydb.h too.
supportproxy.o: supportproxy.cpp mavlink.h util.h keydb.h conntdb.h tlog.h binlog.h session.h cleanup.h websocket.h video.h videots.h
mavlink.o: mavlink.cpp mavlink.h keydb.h $(MAVLINK_DIR)/protocol.h
util.o: util.cpp util.h
keydb.o: keydb.cpp keydb.h
conntdb.o: conntdb.cpp conntdb.h
tlog.o: tlog.cpp tlog.h session.h
session.o: session.cpp session.h
binlog.o: binlog.cpp binlog.h session.h mavlink.h util.h cleanup.h $(MAVLINK_DIR)/protocol.h
cleanup.o: cleanup.cpp cleanup.h keydb.h
websocket.o: websocket.cpp websocket.h util.h
video.o: video.cpp video.h videoauth.h videots.h videostream.h videorec.h videoview.h httpreq.h videortsp.h videortmp.h conntdb.h keydb.h util.h
videoauth.o: videoauth.cpp videoauth.h conntdb.h keydb.h
videots.o: videots.cpp videots.h
videostream.o: videostream.cpp videostream.h
videorec.o: videorec.cpp videorec.h session.h cleanup.h
videoview.o: videoview.cpp videoview.h httpreq.h videostream.h videots.h videoauth.h keydb.h
httpreq.o: httpreq.cpp httpreq.h
videortsp.o: videortsp.cpp videortsp.h
videortmp.o: videortmp.cpp videortmp.h httpreq.h

# Testing
test: $(TARGET)
	@echo "Running basic tests..."
	@echo "Checking if binary was built correctly..."
	@file $(TARGET)
	@echo "Checking if keydb.py is executable..."
	@python3 -m py_compile keydb.py
	@echo "Basic tests passed!"

# Cleaning
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(TARGET) $(OBJECTS)

distclean: clean
	@echo "Cleaning all generated files..."
	rm -rf $(MAVLINK_DIR)

