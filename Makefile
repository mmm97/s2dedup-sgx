######## SGX SDK Settings ########
SGX_SDK	 ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
APP_DIR=App
ENCLAVE_DIR=Enclave
DRIVER_OPENSSL_DIR=Openssl

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	$(error x86 build is not supported, only x64!!)
else
	SGX_COMMON_CFLAGS := -m64 -Wall
	ifeq ($(LINUX_SGX_BUILD), 1)
		include ../../../../buildenv.mk
		SGX_LIBRARY_PATH := $(BUILD_DIR)
		SGX_ENCLAVE_SIGNER := $(BUILD_DIR)/sgx_sign
		SGX_EDGER8R := $(BUILD_DIR)/sgx_edger8r
		SGX_SDK_INC := $(COMMON_DIR)/inc
		STL_PORT_INC := $(LINUX_SDK_DIR)/tlibstdcxx
		SGX_SDK ?= /opt/intel/sgxsdk
	else
		SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
		SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
		SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
		SGX_SDK_INC := $(SGX_SDK)/include
		STL_PORT_INC := $(SGX_SDK_INC)
	endif

endif

ifdef DEBUG
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

# Added to build with SgxSSL libraries
OPENSSL_PACKAGE := /home/gsd/Intel_SGX_SSL/intel-sgx-ssl/Linux/package
SGXSSL_Library_Name := sgx_tsgxssl
OpenSSL_Crypto_Library_Name := sgx_tsgxssl_crypto
TSETJMP_LIB := -lsgx_tsetjmp

ifdef DEBUG
        SGX_COMMON_CFLAGS += -O0 -g
        OPENSSL_LIBRARY_PATH := $(OPENSSL_PACKAGE)/lib64/debug/
else
        SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
        OPENSSL_LIBRARY_PATH := $(OPENSSL_PACKAGE)/lib64/release/
endif


ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

ifeq ($(SGX_MODE), HW)
ifndef DEBUG
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE	
endif
endif
endif

####### Enclave Settings ########

Aux_C_Files :=  $(wildcard $(DRIVER_OPENSSL_DIR)/*.c)
Enclave_C_Files :=  $(wildcard $(ENCLAVE_DIR)/*.c)
Enclave_C_Objects :=  $(Enclave_C_Files:.c=.o) $(Aux_C_Files:.c=.o)

Enclave_Include_Paths := -I$(ENCLAVE_DIR) -I$(DRIVER_OPENSSL_DIR) -I$(SGX_SDK_INC) -I$(SGX_SDK_INC)/tlibc -I$(STL_PORT_INC)/stlport -I$(OPENSSL_PACKAGE)/include -I$(OPENSSL_PACKAGE)/include/openssl

Common_C_Cpp_Flags := -DOS_ID=$(OS_ID) $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpic -fpie -fstack-protector -fno-builtin-printf -Wformat -Wformat-security $(Enclave_Include_Paths) -include "tsgxsslio.h"
Enclave_C_Flags := $(Common_C_Cpp_Flags) -Wno-implicit-function-declaration -std=c11

SgxSSL_Link_Libraries := -L$(OPENSSL_LIBRARY_PATH) -Wl,--whole-archive -l$(SGXSSL_Library_Name) -Wl,--no-whole-archive \
						 -l$(OpenSSL_Crypto_Library_Name)
Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	$(Security_Link_Flags) \
	$(SgxSSL_Link_Libraries) -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcrypto $(TSETJMP_LIB) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(ENCLAVE_DIR)/Enclave.lds
	

ENCLAVE	          = Enclave
PRIVATE_KEY       = Enclave_private.pem
PUBLIC_KEY        = public_key.pem
KEY_SIZE          = 3072
ENCLAVE_EDL       = $(ENCLAVE).edl
ENCLAVE_CONFIG    = $(ENCLAVE).config.xml
OUTPUT_T          = $(ENCLAVE_DIR)/$(ENCLAVE).signed.so
OUTPUT_T_UNSIG    = $(ENCLAVE_DIR)/$(ENCLAVE).so
OUTPUT_U          = libenclave_proxy.a
LIB_DIRS          = -L$(SGX_LIBRARY_PATH)
TRUSTED_OBJECTS   = $(ENCLAVE)_t.o
UNTRUSTED_OBJECTS = $(ENCLAVE)_u.o
TRUSTED_CODE      = $(ENCLAVE)_t.h $(ENCLAVE)_t.c
UNTRUSTED_CODE    = $(ENCLAVE)_u.h $(ENCLAVE)_u.c

####### App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Include_Paths := -I$(DRIVER_OPENSSL_DIR) -I$(APP_DIR) -I$(SGX_SDK)/include 
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

App_srcs := $(wildcard $(APP_DIR)/*.c)
App_objs := $(App_srcs:.c=.o)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
		App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
		App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
		App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread -lcrypto -lzlog

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Name := microbenchmark

#.SILENT:
all: $(App_Name) $(OUTPUT_T)

######## App Objects ########

$(APP_DIR)/Enclave_u.c: $(SGX_EDGER8R) $(ENCLAVE_DIR)/$(ENCLAVE_EDL)
	@cd $(APP_DIR) && $(SGX_EDGER8R) --untrusted ../$(ENCLAVE_DIR)/$(ENCLAVE_EDL) --search-path ../$(ENCLAVE_DIR) --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(APP_DIR)/Enclave_u.o: $(APP_DIR)/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(APP_DIR)/%.o: $(APP_DIR)/%.c $(APP_DIR)/%.h
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(DRIVER_OPENSSL_DIR)/%.o: $(DRIVER_OPENSSL_DIR)/%.c $(DRIVER_OPENSSL_DIR)/%.h
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(App_Name): $(APP_DIR)/Enclave_u.o $(App_objs)
	@$(CC) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

$(ENCLAVE_DIR)/Enclave_t.c: $(SGX_EDGER8R) $(ENCLAVE_DIR)/$(ENCLAVE_EDL)
	@cd Enclave && $(SGX_EDGER8R) --trusted ../$(ENCLAVE_DIR)/$(ENCLAVE_EDL) --search-path ../$(ENCLAVE_DIR) --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(ENCLAVE_DIR)/Enclave_t.o: $(ENCLAVE_DIR)/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(ENCLAVE_DIR)/%.o: $(ENCLAVE_DIR)/%.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $^"

$(OUTPUT_T_UNSIG): $(ENCLAVE_DIR)/Enclave_t.o $(Enclave_C_Objects)
	@$(CC) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(OUTPUT_T): $(OUTPUT_T_UNSIG)
	@$(SGX_ENCLAVE_SIGNER) sign -key $(ENCLAVE_DIR)/$(PRIVATE_KEY) -enclave $(OUTPUT_T_UNSIG) -out $@ -config $(ENCLAVE_DIR)/$(ENCLAVE_CONFIG)
	@echo "SIGN =>  $@"


.PHONY: force_check
force_check:
	true

.PHONY: scrub
scrub: 
	echo "$(INDENT)[RM]  " $(PRIVATE_KEY) $(PUBLIC_KEY)
	$(RM) $(PRIVATE_KEY) $(PUBLIC_KEY)

.PHONY: configure
configure: 
	echo "$(INDENT)[GEN] $(ENCLAVE_DIR)/$(PRIVATE_KEY) ($(KEY_SIZE) bits)"

	# generate 3072 bit private RSA key
	openssl genrsa -out $(ENCLAVE_DIR)/$(PRIVATE_KEY) -3 $(KEY_SIZE)
	
	echo "$(INDENT)[EXT] $(ENCLAVE_DIR)/$(PUBLIC_KEY)"
	# extract public key
	openssl rsa -in $(ENCLAVE_DIR)/$(PRIVATE_KEY) -pubout -out $(ENCLAVE_DIR)/$(PUBLIC_KEY) 
	
	# sign enclave
	#sgx_sign sign -key private_key.pem -enclave Enclave/tresorencl.so -out tresorencl.signed.so
	
.PHONY: clean
clean:
	echo "$(INDENT)[RM]" $(OUTPUT_T_UNSIG) $(OUTPUT_T)
	$(RM) $(OUTPUT_T_UNSIG) $(OUTPUT_T)
	
	echo "$(INDENT)[RM]" $(ENCLAVE_DIR)/Enclave.o $(ENCLAVE_DIR)/Enclave_t.o
	$(RM) $(ENCLAVE_DIR)/Enclave.o $(ENCLAVE_DIR)/Enclave_t.o
	
	echo "$(INDENT)[RM]" $(ENCLAVE_DIR)/Enclave_t.c $(ENCLAVE_DIR)/Enclave_t.h
	$(RM) $(ENCLAVE_DIR)/Enclave_t.c $(ENCLAVE_DIR)/Enclave_t.h
	
	echo "$(INDENT)[RM] $(APP_DIR)/App.o $(APP_DIR)/Enclave_u.o"
	$(RM) $(APP_DIR)/App.o $(APP_DIR)/Enclave_u.o

	echo "$(INDENT)[RM] $(DRIVER_OPENSSL_DIR)/*.o"
	$(RM) $(DRIVER_OPENSSL_DIR)/*.o

	echo "$(INDENT)[RM] $(APP_DIR)/Enclave_u.c $(APP_DIR)/Enclave_u.h"
	$(RM) $(APP_DIR)/Enclave_u.c $(APP_DIR)/Enclave_u.h
	
	echo "$(INDENT)[RM] $(App_Name)"
	$(RM) $(App_Name)
	
