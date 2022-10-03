#include "benchmark_list.h"
#ifdef MVRLU
#include "mvrlu.h"
#else
#include "rlu.h"
#endif

#include <stdio.h>

#define TEST_RLU_MAX_WS 1
#define MAX_ITEMS 128

typedef struct node {
    int leaf;
    int num_items;
    int* items;
	struct node *children[];
} node_t;

typedef struct rlu_btree {
	node_t *root;
    int max_items;
    int min_items;
} rlu_btree_t;

static node_t *rlu_new_node(rlu_btree_t *btree, int leaf)
{
	size_t sz = sizeof(node_t); 
    if (!leaf) {
        sz += sizeof(node_t*)*btree->max_items;
    }
    size_t itemsoff = sz;
    sz += sizeof(int)*(btree->max_items-1);
    node_t *node = RLU_ALLOC(sz);
    if (!node) {
        return NULL;
    }
    node->leaf = leaf;
    node->num_items = 0;
    node->items = (int*)node+itemsoff;
    return node;
}

pthread_data_t *alloc_pthread_data(void)
{
	pthread_data_t *d;
	size_t pthread_size, rlu_size;

#ifndef MVRLU
	pthread_size = sizeof(pthread_data_t);
	pthread_size = CACHE_ALIGN_SIZE(pthread_size);
	rlu_size = sizeof(rlu_thread_data_t);
	rlu_size = CACHE_ALIGN_SIZE(rlu_size);

	d = (pthread_data_t *)malloc(pthread_size + rlu_size);
	if (d != NULL)
		d->ds_data = ((void *)d) + pthread_size;
#else
	pthread_size = sizeof(pthread_data_t);
	pthread_size = CACHE_ALIGN_SIZE(pthread_size);

	d = (pthread_data_t *)malloc(pthread_size);
	if (d != NULL)
		d->ds_data = RLU_THREAD_ALLOC();
#endif



	return d;
}

void free_pthread_data(pthread_data_t *d)
{
	rlu_thread_data_t *rlu_data = (rlu_thread_data_t *)d->ds_data;

	RLU_THREAD_FINISH(rlu_data);

	free(d);
}

static size_t node_find(node_t *node, int key, int *found) 
{
    size_t low = 0;
    size_t high = node->num_items-1;
    size_t index;
    while ( low <= high ) {
        size_t mid = (low + high) / 2;
        int item = node->items[mid];
        if (key == item) {
            *found = 1;
            index = mid;
            return index;
        }
        if (key < item) {
            high = mid - 1;
        } else {
            low = mid + 1;
        }
    }
    *found = 0;
    index = low;
    return index;
}

static void node_shift_right_init(node_t *node, size_t index) {
    memmove(node->items+sizeof(int)*(index+1), 
            node->items+sizeof(int)*index,
            ((size_t)node->num_items-index)*sizeof(int));
    if (!node->leaf) {
        memmove(&node->children[index+1],
                &node->children[index],
                ((size_t)node->num_items-index+1)*sizeof(struct node*));
    }
    node->num_items++;
}

static void node_split_init(rlu_btree_t *btree, node_t *node, node_t **right, int *median) 
{
    size_t mid = (int)(btree->max_items-1)/2;
    *median = node->items[mid];    
    *right = rlu_new_node(btree,node->leaf);
    (*right)->num_items = node->num_items-(mid+1);
    memmove((*right)->items, node->items+(int)sizeof(int)*(mid+1),
            (size_t)(*right)->num_items*sizeof(int));
    if (!node->leaf) {
        for (int i = 0; i <= (*right)->num_items; i++) {
            (*right)->children[i] = node->children[mid+1+i];
        }
    }
    node->num_items = mid;
}

static int node_set_init(rlu_btree_t *btree, node_t *node, int key, int depth) 
{
    int found = 0;
    size_t i = node_find(node, key, &found);
    if (found) {
        return 1;
    }
    if (node->leaf) {
        node_shift_right_init(node, i);
        node->items[i] = key;
        return 0;
    }
    if (node_set_init(btree, node->children[i], key, depth+1)) {
        return 1;
    }
    if ((size_t)node->children[i]->num_items == (btree->max_items-1)) {
        int median = 0;
        node_t *right = NULL;
        node_split_init(btree, node->children[i], &right, &median);
        node_shift_right_init(node, i);
        node->items[i] = median;
        node->children[i+1] = right;
    }
    return 0;
}

int list_ins_init(rlu_btree_t *btree, int key)
{
	node_t *prev, *cur, *new_node;
	int direction, ret, val;
    if (node_set_init(btree, btree->root->children[0], key, 0)) {
        return 0;
    }
    if ((size_t)btree->root->children[0]->num_items == (btree->max_items-1)) {
        node_t *old_root = btree->root->children[0];
        node_t *right = NULL;
        int median = 0;
        node_split_init(btree, old_root, &right, &median);
        btree->root->children[0] = rlu_new_node(btree, 0);
        btree->root->children[0] -> children[0] = old_root;
        btree->root->children[0] -> items[0] = median;
        btree->root->children[0] -> children[1] = right;
        btree->root->children[0] -> num_items = 1;
    }

	return 1;
}


void *list_global_init(int init_size, int value_range)
{
	rlu_btree_t *btree;
	node_t *prev, *cur, *new_node;
	int i, key, val, direction;

	btree = (rlu_btree_t *)malloc(sizeof(rlu_btree_t));
	if (btree == NULL)
		return NULL;
    btree->max_items = MAX_ITEMS;
    btree->min_items = MAX_ITEMS >> 1;
    btree->root = rlu_new_node(btree, 0);
    btree->root->num_items = 0;

	i = 0;
	while (i < init_size) {
		key = rand() % value_range;
        if (!btree->root->children[0]){
            btree->root->children[0] = rlu_new_node(btree, 1);
            btree->root->children[0]->num_items = 1;
            btree->root->children[0]->items[0] = key;
        }
        else{
            list_ins_init(btree, key);
        }
		i++;
	}

	RLU_INIT();

	return btree;
}

int list_thread_init(pthread_data_t *data, pthread_data_t **sync_data, int nr_threads)
{
	rlu_thread_data_t *rlu_data = (rlu_thread_data_t *)data->ds_data;

	RLU_THREAD_INIT(rlu_data);

	return 0;
}

void list_global_exit(void *list)
{
	//free l->head;
}

static void node_shift_right(node_t *node, size_t index) {
    memmove(node->items+sizeof(int)*(index+1), 
            node->items+sizeof(int)*index,
            ((size_t)node->num_items-index)*sizeof(int));
    if (!node->leaf) {
        memmove(&node->children[index+1],
                &node->children[index],
                ((size_t)node->num_items-index+1)*sizeof(struct node*));
    }
    node->num_items++;
}

static void node_shift_left(node_t *node, size_t index, int for_merge) 
{
    memmove(node->items+sizeof(int)*index, 
            node->items+sizeof(int)*(index+1),
            ((size_t)node->num_items-index)*sizeof(int));
    if (!node->leaf) {
        if (for_merge) {
            index++;
        }
        memmove(&node->children[index],
                &node->children[index+1],
                ((size_t)node->num_items-index+1)*sizeof(struct node*));
    }
    node->num_items--;
}

static void node_split(rlu_btree_t *btree, node_t *node, node_t **right, int *median) 
{
    size_t mid = (int)(btree->max_items-1)/2;
    *median = node->items[mid];    
    *right = rlu_new_node(btree,node->leaf);
    (*right)->num_items = node->num_items-(mid+1);
    memmove((*right)->items, node->items+(int)sizeof(int)*(mid+1),
            (size_t)(*right)->num_items*sizeof(int));
    if (!node->leaf) {
        for (int i = 0; i <= (*right)->num_items; i++) {
            (*right)->children[i] = node->children[mid+1+i];
        }
    }
    node->num_items = mid;
}

static int node_set(rlu_btree_t *btree, node_t *node, int key, int depth) 
{
    int found = 0;
    size_t i = node_find(node, key, &found);
    if (found) {
        return 1;
    }
    if (node->leaf) {
        node_shift_right(node, i);
        node->items[i] = key;
        return 0;
    }
    if (node_set(btree, node->children[i], key, depth+1)) {
        return 1;
    }
    if ((size_t)node->children[i]->num_items == (btree->max_items-1)) {
        int median = 0;
        node_t *right = NULL;
        node_split(btree, node->children[i], &right, &median);
        node_shift_right(node, i);
        node->items[i] = median;
        node->children[i+1] = right;
    }
    return 0;
}

/* If the key is inserted return 1; otherwise return 0. */
int list_ins(int key, pthread_data_t *data)
{
	rlu_btree_t *btree = (rlu_btree_t *)data->list;
	rlu_thread_data_t *rlu_data = (rlu_thread_data_t *)data->ds_data;
	node_t *prev, *cur, *new_node;
	int direction, ret, val;

restart:
	RLU_READER_LOCK(rlu_data);

    if (node_set(btree, btree->root->children[0], key, 0)) {
        return 0;
    }
    if ((size_t)btree->root->children[0]->num_items == (btree->max_items-1)) {
        node_t *old_root = btree->root->children[0];
        node_t *right = NULL;
        int median = 0;
        node_split(btree, old_root, &right, &median);
        btree->root->children[0] = rlu_new_node(btree, 0);
        btree->root->children[0]->children[0] = old_root;
        btree->root->children[0]->items[0] = median;
        btree->root->children[0]->children[1] = right;
        btree->root->children[0]->num_items = 1;
    }

	RLU_READER_UNLOCK(rlu_data);

	return 1;
}

enum delact {
    DELKEY, POPMAX
};

static int node_delete(rlu_btree_t *btree, node_t *node, enum delact act, 
    size_t index, int key, int *prev, int depth, rlu_thread_data_t *rlu_data)
{
    size_t i = 0;
    int found = 0;
    switch (act) {
    case POPMAX:
        i = node->num_items-1;
        found = 1;
        break;
    case DELKEY:
        i = node_find(node, key, &found);
        break;
    }
    if (node->leaf) {
        if (found) {
            // item was found in leaf, copy its contents and delete it.
            *prev = node->items[i];
            node_shift_left(node, i, 0);
            return 1;
        }
        return 0;
    }
    // branch
    int deleted = 0;
    if (found) {
        if (act == POPMAX) {
            // popping off the max item into into its parent branch to maintain
            // a balanced tree.
            i++;
            node_delete(btree, node->children[i], POPMAX, 0, NULL,  prev, depth+1, rlu_data);
            deleted = 1;
        } else {
            // item was found in branch, copy its contents, delete it, and 
            // begin popping off the max items in child nodes. 
            *prev = node->items[i];
            int tmp;
            node_delete(btree, node->children[i], POPMAX, 0, NULL, &tmp, depth+1, rlu_data);
            node->items[i] = tmp;
            deleted = 1;
        }
    } else {
        // item was not found in this branch, keep searching.
        deleted = node_delete(btree, node->children[i], act, index, key, prev, depth+1, rlu_data);
    }
    if (!deleted) {
        return 0;
    }
    
    if ((size_t)node->children[i]->num_items >= btree->min_items) {
        return 1;
    }
    
    if (i == node->num_items) {
        i--;
    }

    node_t *left = node->children[i];
    node_t *right = node->children[i+1];

    if ((left->num_items + right->num_items + 1) < 
        (btree->max_items-1)) 
    {
        // merge left + item + right
        left->items[left->num_items] = node->items[i], 
        left->num_items++;
        memcpy(left->items+sizeof(int) * left->num_items, right->items, right->num_items*sizeof(int));
        if (!left->leaf) {
            memcpy(&left->children[left->num_items], &right->children[0], (right->num_items+1)*sizeof(node_t *));
        }
        left->num_items += right->num_items;
        RLU_FREE(rlu_data, right);
        node_shift_left(node, i, 1);
    } else if (left->num_items > right->num_items) {
        // move left -> right
        node_shift_right(right, 0);
        right->items[0] = node->items[i];
        if (!left->leaf) {
            right->children[0] = left->children[left->num_items];
        }
        node->items[i] = left ->items[left->num_items-1]; 
        if (!left->leaf) {
            left->children[left->num_items] = NULL;
        }
        left->num_items--;
    } else {
        // move right -> left
        left->items[left->num_items] = node->items[i];
        if (!left->leaf) {
            left->children[left->num_items+1] = right->children[0];
        }
        left->num_items++;
        node->items[i] = right->items[0];
        node_shift_left(right, 0, 0);
    }
    return deleted;
}


int list_del(int key, pthread_data_t *data)
{
	rlu_btree_t *btree = (rlu_btree_t *)data->list;
	rlu_thread_data_t *rlu_data = (rlu_thread_data_t *)data->ds_data;
	node_t *prev, *cur, *prev_succ, *succ, *next;
	node_t *cur_child_l, *cur_child_r;
	int direction, ret, val;

restart:
	RLU_READER_LOCK(rlu_data);
    int tmp;
    int deleted = node_delete(btree, btree->root->children[0], DELKEY, 0 , key, &tmp, 0, rlu_data);
    if (!deleted) {
        return 0;
    }
    if (btree->root->children[0]->num_items == 0) {
        struct node *old_root = btree->root->children[0];
        if (!btree->root->children[0]->leaf) {
            btree->root->children[0] = btree->root->children[0]->children[0];
        } else {
            btree->root->children[0] = NULL;
        }
        RLU_FREE(rlu_data, old_root);
    }
	RLU_READER_UNLOCK(rlu_data);
	return 1;
}

int list_find(int key, pthread_data_t *data)
{
	rlu_btree_t *btree = (rlu_btree_t *)data->list;
	rlu_thread_data_t *rlu_data = (rlu_thread_data_t *)data->ds_data;
	int ret, val;

	RLU_READER_LOCK(rlu_data);
    node_t *node = btree->root->children[0];
    for (int depth = 0;;depth++) {
        int found = 0;
        size_t i = node_find(node, key, &found);
        if (found) {
	        RLU_READER_UNLOCK(rlu_data);
            return 1;
        }
        if (node->leaf) {
	        RLU_READER_UNLOCK(rlu_data);
            return 0;
        }
        node = node->children[i];
    }

	RLU_READER_UNLOCK(rlu_data);

	return 0;
}