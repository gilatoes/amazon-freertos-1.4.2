AMAZON_FREERTOS_LIB_DIR := ../../../../../../../lib

COMPONENT_SRCDIRS := 	$(AMAZON_FREERTOS_LIB_DIR)/third_party/trustx/pal/esp32_awsfreertos \
						$(AMAZON_FREERTOS_LIB_DIR)/third_party/trustx/optiga/cmd \
						$(AMAZON_FREERTOS_LIB_DIR)/third_party/trustx/optiga/common \
						$(AMAZON_FREERTOS_LIB_DIR)/third_party/trustx/optiga/comms \
						$(AMAZON_FREERTOS_LIB_DIR)/third_party/trustx/optiga/comms/ifx_i2c \
						$(AMAZON_FREERTOS_LIB_DIR)/third_party/trustx/optiga/crypt \
						$(AMAZON_FREERTOS_LIB_DIR)/third_party/trustx/optiga/util
						

COMPONENT_ADD_INCLUDEDIRS := $(AMAZON_FREERTOS_LIB_DIR)/third_party/trustx/optiga/include

