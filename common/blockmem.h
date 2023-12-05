
/*
 * blockmem.h
 * Copyright (C) 2021 Sanjay Rao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#define DEFAULTSIZE_BLOCKMEM	65536
#define _COMMON_BLOCKMEM_H

struct node_blockmem {
	unsigned char *data;
	unsigned int num,max;

	union {
		struct node_blockmem *next;
		struct node_blockmem *next_recycle;
	};
};

struct blockmem {
	struct node_blockmem node;
	union {
		struct node_blockmem *current;
		struct blockmem *next_recycle;
	};
	unsigned int defsize;
};
H_CLEARFUNC(blockmem);

#define strdup_blockmem(a,b) ((char *)memdup_blockmem(a,(unsigned char *)(b),strlen(b)+1))

#define ALLOC_blockmem(a,b) ((b*)alloc_blockmem(a,sizeof(b)))
#define ALLOC2_blockmem(a,b,c) ((b*)alloc_blockmem(a,(c)*sizeof(b)))

void *alloc_blockmem(struct blockmem *blockmem, unsigned int size);
unsigned char *memdup_blockmem(struct blockmem *blockmem, unsigned char *data, unsigned int datalen);
unsigned char *memdupz_blockmem(struct blockmem *blockmem, unsigned char *data, unsigned int datalen);
void voidinit_blockmem(struct blockmem *blockmem, unsigned int size);
int init_blockmem(struct blockmem *blockmem, unsigned int size);
void reset_blockmem(struct blockmem *blockmem);
void deinit_blockmem(struct blockmem *blockmem);
#define strndup_blockmem(a,b,c) strdup2_blockmem(a,(unsigned char *)(b),(unsigned int)(c))
char *strdup2_blockmem(struct blockmem *blockmem, unsigned char *str, unsigned int len);
int addnode_blockmem(struct node_blockmem *node, unsigned int size);
unsigned int sizeof_blockmem(struct blockmem *blockmem);
struct blockmem *new_blockmem(unsigned int size);
