# Project: Tempo

CFLAGS = -O3 -std=c99 -fPIC \
         -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls \
         -Iinclude -Iexternal/openssl/include -Isrc/noic

# add -L and -Wl,-rpath so the dynamic linker can find your .so at runtime
LDFLAGS = -L$(LIB_DIR) -Wl,-rpath,$(LIB_DIR)

SRC_DIR = src
SRC_NOIC_DIR = $(SRC_DIR)/noic
LIB_DIR = lib
OPENSSL_DIR = external/openssl
PQM4_DIR = external/pqm4
OBJ_DIR = obj
OBJ_MLKEM512_DIR  = $(OBJ_DIR)/mlkem512
OBJ_MLKEM768_DIR  = $(OBJ_DIR)/mlkem768
OBJ_MLKEM1024_DIR = $(OBJ_DIR)/mlkem1024
OBJ_SAMPLENTT_DIR = $(OBJ_DIR)/samplentt

OPENSSL_LIB = $(OPENSSL_DIR)/libcrypto.a

SAMPLENTT_OBJ = $(OBJ_DIR)/algorithm_a0.o \
				$(OBJ_DIR)/algorithm_a1.o \
				$(OBJ_DIR)/algorithm_b0.o \
				$(OBJ_DIR)/algorithm_c0.o \
				$(OBJ_DIR)/algorithm_c1.o

FIPS202_OBJ = $(OBJ_DIR)/fips202.o

LIBS =  $(LIB_DIR)/libnoic_mlkem512_a0.so \
        $(LIB_DIR)/libnoic_mlkem512_a1.so \
        $(LIB_DIR)/libnoic_mlkem512_b0.so \
        $(LIB_DIR)/libnoic_mlkem512_c0.so \
        $(LIB_DIR)/libnoic_mlkem512_c1.so \
        $(LIB_DIR)/libnoic_mlkem768_a0.so \
        $(LIB_DIR)/libnoic_mlkem768_a1.so \
        $(LIB_DIR)/libnoic_mlkem768_b0.so \
        $(LIB_DIR)/libnoic_mlkem768_c0.so \
        $(LIB_DIR)/libnoic_mlkem768_c1.so \
        $(LIB_DIR)/libnoic_mlkem1024_a0.so \
        $(LIB_DIR)/libnoic_mlkem1024_a1.so \
        $(LIB_DIR)/libnoic_mlkem1024_b0.so \
        $(LIB_DIR)/libnoic_mlkem1024_c0.so \
        $(LIB_DIR)/libnoic_mlkem1024_c1.so

# ML-KEM headers
HEADERS =	$(SRC_NOIC_DIR)/api.h $(SRC_NOIC_DIR)/cbd.h \
			$(SRC_NOIC_DIR)/fips202.h $(SRC_NOIC_DIR)/indcpa.h \
			$(SRC_NOIC_DIR)/kem.h $(SRC_NOIC_DIR)/ntt.h \
			$(SRC_NOIC_DIR)/params.h $(SRC_NOIC_DIR)/poly.h \
			$(SRC_NOIC_DIR)/polyvec.h $(SRC_NOIC_DIR)/randombytes.h \
			$(SRC_NOIC_DIR)/reduce.h $(SRC_NOIC_DIR)/symmetric.h \
			$(SRC_NOIC_DIR)/verify.h \
			$(SRC_NOIC_DIR)/pake.h $(SRC_NOIC_DIR)/twofeistel.h

all:	$(OPENSSL_LIB) $(OBJ_MLKEM512_DIR) $(OBJ_MLKEM768_DIR) \
		$(OBJ_MLKEM1024_DIR) $(OBJ_SAMPLENTT_DIR) $(LIB_DIR) $(LIBS)

# compile OpenSSL
$(OPENSSL_LIB):
	cd $(OPENSSL_DIR) && ./config && make

# create object dirs
$(OBJ_MLKEM512_DIR) $(OBJ_MLKEM768_DIR) $(OBJ_MLKEM1024_DIR) $(OBJ_SAMPLENTT_DIR) $(LIB_DIR):
	mkdir -p $@

# MLKEM objects, except (a) indcpa_<variant>.o and (b) algorithm_<variant>.o
# (a) indcpa_<variant>.o requires flag -DSAMPLENTT to select the SampleNTT algorithm
# (b) algorithm_<variant>.o are the same regardless of KYBER_K
MLKEM512_OBJ =	$(OBJ_MLKEM512_DIR)/cbd.o $(OBJ_MLKEM512_DIR)/fips202.o \
				$(OBJ_MLKEM512_DIR)/kem.o $(OBJ_MLKEM512_DIR)/ntt.o \
				$(OBJ_MLKEM512_DIR)/poly.o $(OBJ_MLKEM512_DIR)/polyvec.o \
            	$(OBJ_MLKEM512_DIR)/randombytes.o $(OBJ_MLKEM512_DIR)/reduce.o \
            	$(OBJ_MLKEM512_DIR)/symmetric-shake.o $(OBJ_MLKEM512_DIR)/verify.o \
				$(OBJ_MLKEM512_DIR)/pake.o

MLKEM768_OBJ =	$(OBJ_MLKEM768_DIR)/cbd.o $(OBJ_MLKEM768_DIR)/fips202.o \
				$(OBJ_MLKEM768_DIR)/kem.o $(OBJ_MLKEM768_DIR)/ntt.o \
				$(OBJ_MLKEM768_DIR)/poly.o $(OBJ_MLKEM768_DIR)/polyvec.o \
            	$(OBJ_MLKEM768_DIR)/randombytes.o $(OBJ_MLKEM768_DIR)/reduce.o \
            	$(OBJ_MLKEM768_DIR)/symmetric-shake.o $(OBJ_MLKEM768_DIR)/verify.o \
				$(OBJ_MLKEM768_DIR)/pake.o

MLKEM1024_OBJ =	$(OBJ_MLKEM1024_DIR)/cbd.o $(OBJ_MLKEM1024_DIR)/fips202.o \
				$(OBJ_MLKEM1024_DIR)/kem.o $(OBJ_MLKEM1024_DIR)/ntt.o \
				$(OBJ_MLKEM1024_DIR)/poly.o $(OBJ_MLKEM1024_DIR)/polyvec.o \
            	$(OBJ_MLKEM1024_DIR)/randombytes.o $(OBJ_MLKEM1024_DIR)/reduce.o \
            	$(OBJ_MLKEM1024_DIR)/symmetric-shake.o $(OBJ_MLKEM1024_DIR)/verify.o \
				$(OBJ_MLKEM1024_DIR)/verify.o \
				$(OBJ_MLKEM1024_DIR)/pake.o

# SampleNTT objects
SAMPLENTT_OBJ = $(OBJ_SAMPLENTT_DIR)/algorithm_a0.o $(OBJ_SAMPLENTT_DIR)/algorithm_a1.o \
				$(OBJ_SAMPLENTT_DIR)/algorithm_b0.o $(OBJ_SAMPLENTT_DIR)/algorithm_c0.o \
				$(OBJ_SAMPLENTT_DIR)/algorithm_c1.o

# MLKEM from source to object, per KYBER_K
$(OBJ_MLKEM512_DIR)/%.o: $(SRC_NOIC_DIR)/%.c $(HEADERS) | $(OBJ_MLKEM512_DIR)
	$(CC) $(CFLAGS) -DKYBER_K=2 -c -o $@ $<

$(OBJ_MLKEM768_DIR)/%.o: $(SRC_NOIC_DIR)/%.c $(HEADERS) | $(OBJ_MLKEM768_DIR)
	$(CC) $(CFLAGS) -DKYBER_K=3 -c -o $@ $<

$(OBJ_MLKEM1024_DIR)/%.o: $(SRC_NOIC_DIR)/%.c $(HEADERS) | $(OBJ_MLKEM1024_DIR)
	$(CC) $(CFLAGS) -DKYBER_K=4 -c -o $@ $<

# SampleNTT from source to object
$(OBJ_SAMPLENTT_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

# indcpa variants from source to object, for each KYBER_K and SAMPLENTT
$(OBJ_MLKEM512_DIR)/indcpa_a0.o: $(SRC_NOIC_DIR)/indcpa.c $(OBJ_SAMPLENTT_DIR)/algorithm_a0.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=2 -DSAMPLENTT=10 -c -o $@ $<
$(OBJ_MLKEM512_DIR)/indcpa_a1.o: $(SRC_NOIC_DIR)/indcpa.c $(OBJ_SAMPLENTT_DIR)/algorithm_a1.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=2 -DSAMPLENTT=11 -c -o $@ $<
$(OBJ_MLKEM512_DIR)/indcpa_b0.o: $(SRC_NOIC_DIR)/indcpa.c $(OBJ_SAMPLENTT_DIR)/algorithm_b0.o $(HEADERS) $(OPENSSL_LIB)
	$(CC) $(CFLAGS) -DKYBER_K=2 -DSAMPLENTT=20 -c -o $@ $<
$(OBJ_MLKEM512_DIR)/indcpa_c0.o: $(SRC_NOIC_DIR)/indcpa.c $(OBJ_SAMPLENTT_DIR)/algorithm_c0.o $(HEADERS) $(OPENSSL_LIB)
	$(CC) $(CFLAGS) -DKYBER_K=2 -DSAMPLENTT=30 -c -o $@ $<
$(OBJ_MLKEM512_DIR)/indcpa_c1.o: $(SRC_NOIC_DIR)/indcpa.c $(OBJ_SAMPLENTT_DIR)/algorithm_c1.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=2 -DSAMPLENTT=31 -c -o $@ $<

$(OBJ_MLKEM768_DIR)/indcpa_a0.o: $(SRC_NOIC_DIR)/indcpa.c $(OBJ_SAMPLENTT_DIR)/algorithm_a0.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=3 -DSAMPLENTT=10 -c -o $@ $<
$(OBJ_MLKEM768_DIR)/indcpa_a1.o: $(SRC_NOIC_DIR)/indcpa.c $(OBJ_SAMPLENTT_DIR)/algorithm_a1.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=3 -DSAMPLENTT=11 -c -o $@ $<
$(OBJ_MLKEM768_DIR)/indcpa_b0.o: $(SRC_NOIC_DIR)/indcpa.c $(OBJ_SAMPLENTT_DIR)/algorithm_b0.o $(HEADERS) $(OPENSSL_LIB)
	$(CC) $(CFLAGS) -DKYBER_K=3 -DSAMPLENTT=20 -c -o $@ $<
$(OBJ_MLKEM768_DIR)/indcpa_c0.o: $(SRC_NOIC_DIR)/indcpa.c $(OBJ_SAMPLENTT_DIR)/algorithm_c0.o $(HEADERS) $(OPENSSL_LIB)
	$(CC) $(CFLAGS) -DKYBER_K=3 -DSAMPLENTT=30 -c -o $@ $<
$(OBJ_MLKEM768_DIR)/indcpa_c1.o: $(SRC_NOIC_DIR)/indcpa.c $(OBJ_SAMPLENTT_DIR)/algorithm_c1.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=3 -DSAMPLENTT=31 -c -o $@ $<

$(OBJ_MLKEM1024_DIR)/indcpa_a0.o: $(SRC_NOIC_DIR)/indcpa.c $(OBJ_SAMPLENTT_DIR)/algorithm_a0.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=4 -DSAMPLENTT=10 -c -o $@ $<
$(OBJ_MLKEM1024_DIR)/indcpa_a1.o: $(SRC_NOIC_DIR)/indcpa.c $(OBJ_SAMPLENTT_DIR)/algorithm_a1.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=4 -DSAMPLENTT=11 -c -o $@ $<
$(OBJ_MLKEM1024_DIR)/indcpa_b0.o: $(SRC_NOIC_DIR)/indcpa.c $(OBJ_SAMPLENTT_DIR)/algorithm_b0.o $(HEADERS) $(OPENSSL_LIB)
	$(CC) $(CFLAGS) -DKYBER_K=4 -DSAMPLENTT=20 -c -o $@ $<
$(OBJ_MLKEM1024_DIR)/indcpa_c0.o: $(SRC_NOIC_DIR)/indcpa.c $(OBJ_SAMPLENTT_DIR)/algorithm_c0.o $(HEADERS) $(OPENSSL_LIB)
	$(CC) $(CFLAGS) -DKYBER_K=4 -DSAMPLENTT=30 -c -o $@ $<
$(OBJ_MLKEM1024_DIR)/indcpa_c1.o: $(SRC_NOIC_DIR)/indcpa.c $(OBJ_SAMPLENTT_DIR)/algorithm_c1.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=4 -DSAMPLENTT=31 -c -o $@ $<

# twofeistel variants from source to object, for each KYBER_K and SAMPLENTT
$(OBJ_MLKEM512_DIR)/twofeistel_a0.o: $(SRC_NOIC_DIR)/twofeistel.c $(OBJ_SAMPLENTT_DIR)/algorithm_a0.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=2 -DSAMPLENTT=10 -c -o $@ $<
$(OBJ_MLKEM512_DIR)/twofeistel_a1.o: $(SRC_NOIC_DIR)/twofeistel.c $(OBJ_SAMPLENTT_DIR)/algorithm_a1.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=2 -DSAMPLENTT=11 -c -o $@ $<
$(OBJ_MLKEM512_DIR)/twofeistel_b0.o: $(SRC_NOIC_DIR)/twofeistel.c $(OBJ_SAMPLENTT_DIR)/algorithm_b0.o $(HEADERS) $(OPENSSL_LIB)
	$(CC) $(CFLAGS) -DKYBER_K=2 -DSAMPLENTT=20 -c -o $@ $<
$(OBJ_MLKEM512_DIR)/twofeistel_c0.o: $(SRC_NOIC_DIR)/twofeistel.c $(OBJ_SAMPLENTT_DIR)/algorithm_c0.o $(HEADERS) $(OPENSSL_LIB)
	$(CC) $(CFLAGS) -DKYBER_K=2 -DSAMPLENTT=30 -c -o $@ $<
$(OBJ_MLKEM512_DIR)/twofeistel_c1.o: $(SRC_NOIC_DIR)/twofeistel.c $(OBJ_SAMPLENTT_DIR)/algorithm_c1.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=2 -DSAMPLENTT=31 -c -o $@ $<

$(OBJ_MLKEM768_DIR)/twofeistel_a0.o: $(SRC_NOIC_DIR)/twofeistel.c $(OBJ_SAMPLENTT_DIR)/algorithm_a0.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=3 -DSAMPLENTT=10 -c -o $@ $<
$(OBJ_MLKEM768_DIR)/twofeistel_a1.o: $(SRC_NOIC_DIR)/twofeistel.c $(OBJ_SAMPLENTT_DIR)/algorithm_a1.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=3 -DSAMPLENTT=11 -c -o $@ $<
$(OBJ_MLKEM768_DIR)/twofeistel_b0.o: $(SRC_NOIC_DIR)/twofeistel.c $(OBJ_SAMPLENTT_DIR)/algorithm_b0.o $(HEADERS) $(OPENSSL_LIB)
	$(CC) $(CFLAGS) -DKYBER_K=3 -DSAMPLENTT=20 -c -o $@ $<
$(OBJ_MLKEM768_DIR)/twofeistel_c0.o: $(SRC_NOIC_DIR)/twofeistel.c $(OBJ_SAMPLENTT_DIR)/algorithm_c0.o $(HEADERS) $(OPENSSL_LIB)
	$(CC) $(CFLAGS) -DKYBER_K=3 -DSAMPLENTT=30 -c -o $@ $<
$(OBJ_MLKEM768_DIR)/twofeistel_c1.o: $(SRC_NOIC_DIR)/twofeistel.c $(OBJ_SAMPLENTT_DIR)/algorithm_c1.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=3 -DSAMPLENTT=31 -c -o $@ $<

$(OBJ_MLKEM1024_DIR)/twofeistel_a0.o: $(SRC_NOIC_DIR)/twofeistel.c $(OBJ_SAMPLENTT_DIR)/algorithm_a0.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=4 -DSAMPLENTT=10 -c -o $@ $<
$(OBJ_MLKEM1024_DIR)/twofeistel_a1.o: $(SRC_NOIC_DIR)/twofeistel.c $(OBJ_SAMPLENTT_DIR)/algorithm_a1.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=4 -DSAMPLENTT=11 -c -o $@ $<
$(OBJ_MLKEM1024_DIR)/twofeistel_b0.o: $(SRC_NOIC_DIR)/twofeistel.c $(OBJ_SAMPLENTT_DIR)/algorithm_b0.o $(HEADERS) $(OPENSSL_LIB)
	$(CC) $(CFLAGS) -DKYBER_K=4 -DSAMPLENTT=20 -c -o $@ $<
$(OBJ_MLKEM1024_DIR)/twofeistel_c0.o: $(SRC_NOIC_DIR)/twofeistel.c $(OBJ_SAMPLENTT_DIR)/algorithm_c0.o $(HEADERS) $(OPENSSL_LIB)
	$(CC) $(CFLAGS) -DKYBER_K=4 -DSAMPLENTT=30 -c -o $@ $<
$(OBJ_MLKEM1024_DIR)/twofeistel_c1.o: $(SRC_NOIC_DIR)/twofeistel.c $(OBJ_SAMPLENTT_DIR)/algorithm_c1.o $(HEADERS)
	$(CC) $(CFLAGS) -DKYBER_K=4 -DSAMPLENTT=31 -c -o $@ $<

# fips202 object
$(FIPS202_OBJ): $(SRC_NOIC_DIR)/fips202.c
	$(CC) $(CFLAGS) -c -o $@ $<

# libraries
# indcpa.c always calls algorithmA0, so algorithm_a0.o must be linked into every
# variant (duplicates are dropped by $^ for the a0 variant itself).
$(LIB_DIR)/libnoic_mlkem512_%.so: 	$(MLKEM512_OBJ) \
								$(OBJ_MLKEM512_DIR)/indcpa_%.o \
								$(OBJ_MLKEM512_DIR)/twofeistel_%.o \
								$(OBJ_SAMPLENTT_DIR)/algorithm_%.o \
								$(OBJ_SAMPLENTT_DIR)/algorithm_a0.o
	$(CC) -shared -o $@ $^ $(OPENSSL_LIB)

$(LIB_DIR)/libnoic_mlkem768_%.so:	$(MLKEM768_OBJ) \
								$(OBJ_MLKEM768_DIR)/indcpa_%.o \
								$(OBJ_MLKEM768_DIR)/twofeistel_%.o \
								$(OBJ_SAMPLENTT_DIR)/algorithm_%.o \
								$(OBJ_SAMPLENTT_DIR)/algorithm_a0.o
	$(CC) -shared -o $@ $^ $(OPENSSL_LIB)

$(LIB_DIR)/libnoic_mlkem1024_%.so:	$(MLKEM1024_OBJ) \
								$(OBJ_MLKEM1024_DIR)/indcpa_%.o \
								$(OBJ_MLKEM1024_DIR)/twofeistel_%.o \
								$(OBJ_SAMPLENTT_DIR)/algorithm_%.o \
								$(OBJ_SAMPLENTT_DIR)/algorithm_a0.o
	$(CC) -shared -o $@ $^ $(OPENSSL_LIB)

$(LIB_DIR)/libsamplentt.so: $(SAMPLENTT_OBJ) $(FIPS202_OBJ) $(OPENSSL_LIB)
	$(CC) -shared -o $@ $^

clean:
	$(RM) -r $(OBJ_DIR)
	$(RM) -r $(LIB_DIR)
	rm -rf external/pqm4/crypto_kem/noic-a0-mlkem512
	rm -rf external/pqm4/crypto_kem/noic-a0-mlkem768
	rm -rf external/pqm4/crypto_kem/noic-a0-mlkem1024
	rm -rf external/pqm4/crypto_kem/noic-a1-mlkem512
	rm -rf external/pqm4/crypto_kem/noic-a1-mlkem768
	rm -rf external/pqm4/crypto_kem/noic-a1-mlkem1024
	rm -rf external/pqm4/crypto_kem/noic-c1-mlkem512
	rm -rf external/pqm4/crypto_kem/noic-c1-mlkem768
	rm -rf external/pqm4/crypto_kem/noic-c1-mlkem1024
	rm -rf external/pqm4/crypto_kem/tempo-a1-mlkem512
	rm -rf external/pqm4/crypto_kem/tempo-a1-mlkem768
	rm -rf external/pqm4/crypto_kem/tempo-a1-mlkem1024
	rm -rf external/pqm4/crypto_kem/tempo-c1-mlkem512
	rm -rf external/pqm4/crypto_kem/tempo-c1-mlkem768
	rm -rf external/pqm4/crypto_kem/tempo-c1-mlkem1024
#	cd $(OPENSSL_DIR) && make clean
#	cd $(PQM4_DIR) && make clean

# copy pake construction to pqm4
copy-pakes:
	cp -R src/pqm4/crypto_kem/noic-a0-mlkem512 external/pqm4/crypto_kem/
	cp -R src/pqm4/crypto_kem/noic-a0-mlkem768 external/pqm4/crypto_kem/
	cp -R src/pqm4/crypto_kem/noic-a0-mlkem1024 external/pqm4/crypto_kem/
	cp -R src/pqm4/crypto_kem/noic-a1-mlkem512 external/pqm4/crypto_kem/
	cp -R src/pqm4/crypto_kem/noic-a1-mlkem768 external/pqm4/crypto_kem/
	cp -R src/pqm4/crypto_kem/noic-a1-mlkem1024 external/pqm4/crypto_kem/
	cp -R src/pqm4/crypto_kem/noic-c1-mlkem512 external/pqm4/crypto_kem/
	cp -R src/pqm4/crypto_kem/noic-c1-mlkem768 external/pqm4/crypto_kem/
	cp -R src/pqm4/crypto_kem/noic-c1-mlkem1024 external/pqm4/crypto_kem/
	cp -R src/pqm4/crypto_kem/tempo-a1-mlkem512 external/pqm4/crypto_kem/
	cp -R src/pqm4/crypto_kem/tempo-a1-mlkem768 external/pqm4/crypto_kem/
	cp -R src/pqm4/crypto_kem/tempo-a1-mlkem1024 external/pqm4/crypto_kem/
	cp -R src/pqm4/crypto_kem/tempo-c1-mlkem512 external/pqm4/crypto_kem/
	cp -R src/pqm4/crypto_kem/tempo-c1-mlkem768 external/pqm4/crypto_kem/
	cp -R src/pqm4/crypto_kem/tempo-c1-mlkem1024 external/pqm4/crypto_kem/

# keep intermediate object files; do not auto-rm them after building .so
.SECONDARY:
