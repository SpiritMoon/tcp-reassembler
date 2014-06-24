#ifndef MY_HASH_H
#define MY_HASH_H

#include <stdlib.h>
#include <string.h>

#define DEF_HASH_SIZE 10000

typedef size_t (*HASHFUNC)(const char *);
typedef void (*FREEFUNC)(void *);

typedef struct hashnode_s HASHNODE;
struct hashnode_s {
	char *key;
	void *data;
	HASHNODE *next;
};

typedef struct {
	size_t size;
	HASHNODE **nodes;
	HASHFUNC hashfunc;
    FREEFUNC freefunc;
} HASHTBL;

typedef struct {
    size_t cindex;
    size_t nindex;
    HASHTBL *hashtbl;
} HASHITR;


extern size_t def_hashfunc(const char *key);
extern size_t hash_key(HASHFUNC hashfunc, const char *key);
extern void free_data(FREEFUNC freefunc, void *data);
extern HASHTBL *hashtbl_create(size_t size, HASHFUNC hashfunc, FREEFUNC freefunc);
extern HASHNODE *hashtbl_get(HASHTBL *hashtbl, const char *key);
extern size_t hashtbl_index(HASHTBL *hashtbl, const char *key);
extern tBool hashtbl_key_exist(HASHTBL *hashtbl, const char *key);
extern size_t hashtbl_insert(HASHTBL *hashtbl, const char *key, void *data);
extern size_t hashtbl_remove(HASHTBL *hashtbl, const char *key);
extern size_t hashtbl_remove_n(HASHNODE *node, size_t count, FREEFUNC freefunc);
extern void hashtbl_empty(HASHTBL *hashtbl);
extern void hashtbl_destroy(HASHTBL *hashtbl);
extern HASHITR hashtbl_iterator(HASHTBL *hashtbl);
extern HASHNODE *hashtbl_next(HASHITR *pitr);
// global single hash table
extern HASHTBL *get_hash_table();
extern HASHTBL *set_hash_table(HASHFUNC hashfunc, FREEFUNC freefunc);
extern HASHTBL *set_hash_hashfunc(HASHFUNC hashfunc);
extern HASHTBL *set_hash_freefunc(FREEFUNC freefunc);
extern HASHNODE *get_hash_nodes(const char *key);
extern size_t get_hash_index(const char *key);
extern tBool is_hash_key_exist(const char *key);
extern size_t insert_hash_node(const char *key, void *data);
extern size_t remove_hash_node(HASHNODE *node);
extern size_t remove_hash_nodes(const char *key);
extern void empty_hash_table();
extern void destroy_hash_table();

#endif /* MY_HASH_H */
