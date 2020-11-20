# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2020 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = pingpong

# all source are stored in SRCS-y
SRCS-y := main.c

CFLAGS += -O3 -Wdeprecated-declarations
CFLAGS += $(WERROR_FLAGS)

include $(RTE_SDK)/mk/rte.extapp.mk
