#include "benchmark_list.h"
#include "mvrlu.h"

#include <stdio.h>
#include <string.h>

#define TEST_RLU_MAX_WS 1
#define MAX_ITEMS 4

typedef struct node {
    int leaf;
    int num_items;
    int size;
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
    node->size = sz;
    node->items = (int*)((void *)node+itemsoff);
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

static void node_print(rlu_btree_t *btree, node_t *node, int depth, rlu_thread_data_t *rlu_data) 
{
    if (node->leaf) {
        for (int i = 0; i < depth; i++) {
            printf("  ");
        }
        printf("[");
        for (int i = 0; i < node->num_items; i++) {
            if (i > 0) {
                printf(" ");
            }
            printf("%d", node->items[i]);
        }
        printf("]\n");
    } else {
        for (short i = 0; i < node->num_items; i++) {
            node_t *child = RLU_DEREF(rlu_data, (node->children[i]));
            node_print(btree, child, depth+1, rlu_data);
            for (int j = 0; j < depth; j++) {
                printf("  ");
            }
            printf("%d", node->items[i]);
            printf("\n");
        }
        node_t *child = RLU_DEREF(rlu_data, (node->children[node->num_items]));
        node_print(btree, child, depth+1, rlu_data);
    }
}

void free_pthread_data(pthread_data_t *d)
{
	rlu_thread_data_t *rlu_data = (rlu_thread_data_t *)d->ds_data;
	
    rlu_btree_t *btree = (rlu_btree_t *)d->list;
    node_t *root = RLU_DEREF(rlu_data, (btree->root->children[0]));
    node_print(btree, root, 0, rlu_data);

	RLU_THREAD_FINISH(rlu_data);

	free(d);
}

static int node_find(node_t *node, int key, int *found) 
{
    if (node->num_items == 0) {
        *found = 0;
        return 0;
    }
    int low = 0;
    int high = node->num_items-1;
    int index;
    while ( low <= high ) {
        int mid = (low + high) / 2;
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
    memmove(&node->items[index+1], 
            &node->items[index],
            ((size_t)node->num_items-index)*sizeof(int));
    if (!node->leaf) {
        memmove(&node->children[index+1],
                &node->children[index],
                ((size_t)node->num_items-index+1)*sizeof(node_t *));
    }
    node->num_items++;
}

static void node_split_init(rlu_btree_t *btree, node_t *node, node_t **right, int *median) 
{
    int mid = (int)(btree->max_items-1)/2;
    *median = node->items[mid];    
    *right = rlu_new_node(btree, node->leaf);
    (*right)->num_items = node->num_items-(mid+1);
    memmove((*right)->items, &node->items[mid+1],
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
    int i = node_find(node, key, &found);
    if (found) {
        return 1;
    }
    if (node->leaf) {
        node_shift_right_init(node, (size_t)i);
        node->items[(size_t)i] = key;
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
	int i, key;

	btree = (rlu_btree_t *)malloc(sizeof(rlu_btree_t));
	if (btree == NULL)
		return NULL;
    btree->max_items = MAX_ITEMS;
    btree->min_items = (MAX_ITEMS << 2) / 10;
    btree->root = rlu_new_node(btree, 0);
    btree->root->num_items = 0;
    btree->root->children[0] = NULL;

	i = 0;
	while (i < init_size) {
		key = rand() % value_range;
        if (!btree->root->children[0]){
            node_t *node = rlu_new_node(btree, 1);
            node->num_items = 1;
            node->items[0] = key;
            btree->root->children[0] = node;
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
    memmove(&node->items[index+1], 
            &node->items[index],
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
    memmove(&node->items[index], 
            &node->items[index+1],
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

static void node_split(rlu_btree_t *btree, node_t *node, node_t **right, int *median, rlu_thread_data_t *rlu_data) 
{
    int mid = (int)(btree->max_items-1)/2;
    *median = node->items[mid];    
    *right = rlu_new_node(btree,node->leaf);
    (*right)->num_items = node->num_items-(mid+1);
    memmove((*right)->items, &node->items[mid+1],
            (size_t)(*right)->num_items*sizeof(int));
    if (!node->leaf) {
        for (int i = 0; i <= (*right)->num_items; i++) {
            RLU_ASSIGN_PTR(rlu_data, &((*right)->children[i]), node->children[mid + 1 + i]);
        }
    }
    node->num_items = mid;
}
/*with_lock = 1 represent node_set holds the lock for this level. Otherwise only deref.*/
static int node_set(rlu_btree_t *btree, node_t **node, int key, int depth, int *with_lock, pthread_data_t *data) 
{
    int found = 0;
	rlu_thread_data_t *rlu_data = (rlu_thread_data_t *)data->ds_data;
    int i = node_find((*node), key, &found);
    if (found) {
        *with_lock = 0;
        return 1;
    }
    if ((*node)->leaf) {
        if(!_mvrlu_try_lock(rlu_data, (void**)node, (*node)->size)){
            data->nr_abort++;
            return -1;
        }
        node_shift_right((*node), (size_t)i);
        (*node)->items[i] = key;
        *with_lock = 1;
        return 0;
    }
    
    node_t *child = (node_t *)RLU_DEREF(rlu_data, ((*node)->children[i]));
    int with_lock_child;
    int ret = node_set(btree, &child, key, depth+1, &with_lock_child, data);
    if (ret == 1) {
        *with_lock = 0;
        return 1;
    }
    else if (ret == -1)
    {
        return -1;
    }
    
    if ((size_t)child->num_items == (btree->max_items-1)) {
        int median = 0;
        node_t *right = NULL;
        if (with_lock_child == 0){
            if (!_mvrlu_try_lock(rlu_data, (void **)(&child), child->size) || !_mvrlu_try_lock(rlu_data, (void **)node, (*node)->size)){
                data->nr_abort++;
                return -1;
            }
        }
        else if (with_lock_child == 1)
        {
            if (!_mvrlu_try_lock(rlu_data, (void **)node, (*node)->size)){
                data->nr_abort++;
                return -1;
            }
        }
        node_split(btree, child, &right, &median, rlu_data);
        node_shift_right((*node), (size_t)i);
        (*node)->items[i] = median;
        RLU_ASSIGN_PTR(rlu_data, &((*node)->children[i+1]), right);
        *with_lock = 1;
    }
    return 0;
}

/* If the key is inserted return 1; otherwise return 0. */
int list_ins(int key, pthread_data_t *data)
{
	rlu_btree_t *btree = (rlu_btree_t *)data->list;
	rlu_thread_data_t *rlu_data = (rlu_thread_data_t *)data->ds_data;
	node_t *prev, *cur, *new_node;
	int with_lock, ret;

restart:
	RLU_READER_LOCK(rlu_data);
    prev = (node_t *)RLU_DEREF(rlu_data, (btree->root));
    cur = (node_t *)RLU_DEREF(rlu_data, (prev->children[0]));
    ret = node_set(btree, &cur, key, 0, &with_lock, data);
    if (ret == 1) {
        RLU_READER_UNLOCK(rlu_data);
        return 0;
    }
    else if (ret == -1)
    {
        RLU_ABORT(rlu_data);
        goto restart;
    }
    
    if ((size_t)cur->num_items == (btree->max_items-1)) {
        node_t *right = NULL;
        int median = 0;
        if (with_lock == 0){
            if (!_mvrlu_try_lock(rlu_data, (void **)(&cur), cur->size) || !_mvrlu_try_lock(rlu_data, (void **)(&prev), prev->size)){
                data->nr_abort++;
                RLU_ABORT(rlu_data);
                goto restart;
            }
        }
        else if (with_lock == 1)
        {
            if (!_mvrlu_try_lock(rlu_data, (void **)(&prev), prev->size)){
                data->nr_abort++;
                RLU_ABORT(rlu_data);
                goto restart;
            }
        }
        node_split(btree, cur, &right, &median, rlu_data);
        new_node = rlu_new_node(btree, 0);
        new_node->items[0] = median;
        new_node->num_items = 1;
        RLU_ASSIGN_PTR(rlu_data, &(new_node->children[0]), (cur));
        RLU_ASSIGN_PTR(rlu_data, &(new_node->children[1]), (right));
        RLU_ASSIGN_PTR(rlu_data, &(prev->children[0]), new_node);
    }

	RLU_READER_UNLOCK(rlu_data);

	return 1;
}

enum delact {
    DELKEY, POPMAX
};

static int node_delete(rlu_btree_t *btree, node_t **node, enum delact act, 
    size_t index, int key, int *prev, int depth, int *with_lock, pthread_data_t *data)
{
	rlu_thread_data_t *rlu_data = (rlu_thread_data_t *)data->ds_data;
    int i = 0;
    int found = 0;
    switch (act) {
    case POPMAX:
        i = (*node)->num_items-1;
        found = 1;
        break;
    case DELKEY:
        i = node_find((*node), key, &found);
        break;
    }
    if ((*node)->leaf) {
        if (found) {
            // item was found in leaf, copy its contents and delete it.
            *prev = (*node)->items[(size_t)i];
            if (!_mvrlu_try_lock(rlu_data, (void **)node, (*node)->size)){
                data->nr_abort++;
                return -1;
            }
            node_shift_left((*node), (size_t)i, 0);
            *with_lock = 1;
            return 1;
        }
        *with_lock = 0;
        return 0;
    }
    // branch
    int deleted = 0;
    int ret, with_lock_child = 0;
    node_t *child = RLU_DEREF(rlu_data, ((*node)->children[i]));
    int j = i;
    if (found) {
        if (act == POPMAX) {
            // popping off the max item into into its parent branch to maintain
            // a balanced tree.
            i++;
            ret = node_delete(btree, &child, POPMAX, 0, 0, prev, depth+1, &with_lock_child, data);
            if (ret == -1) return -1;
            deleted = 1;
        } else {
            // item was found in branch, copy its contents, delete it, and 
            // begin popping off the max items in child nodes. 
            *prev = (*node)->items[(size_t)i];
            int tmp;
            ret = node_delete(btree, &child, POPMAX, 0, 0, &tmp, depth+1, &with_lock_child, data);
            if (ret == -1) return -1;
            if (!_mvrlu_try_lock(rlu_data, (void **)node, (*node)->size)){
                data->nr_abort++;
                return -1;
            }
            (*node)->items[(size_t)i] = tmp;
            *with_lock = 1;
            deleted = 1;
        }
    } else {
        // item was not found in this branch, keep searching.
        deleted = node_delete(btree, &child, act, index, key, prev, depth+1, &with_lock_child, data);
    }

    if (deleted == 0) {
        return 0;
    }
    else if (deleted == -1)
    {
        return -1;
    }
    
    
    if ((size_t)child->num_items >= btree->min_items) {
        return 1;
    }
    
    if (i == (*node)->num_items) {
        i--;
    }
    
    node_t *left = (node_t *)RLU_DEREF(rlu_data, ((*node)->children[i]));
    node_t *right = (node_t *)RLU_DEREF(rlu_data, ((*node)->children[i+1]));
    if (j != i && j != i+1){
        if(!_mvrlu_try_lock(rlu_data, (void **)(&left), left->size) || !_mvrlu_try_lock(rlu_data, (void **)(&right), right->size)){
            data->nr_abort++;
            return -1;
        }
    } else if (j == i){
        left = child;
        if (with_lock_child){
            if (!_mvrlu_try_lock(rlu_data, (void **)(&right), right->size)){
                data->nr_abort++;
                return -1;
            }
        } else {
            if(!_mvrlu_try_lock(rlu_data, (void **)(&left), left->size) || !_mvrlu_try_lock(rlu_data, (void **)(&right), right->size)){
                data->nr_abort++;
                return -1;
            }
        }
    } else if (j == i+1){
        right = child;
        if (with_lock_child){
            if (!_mvrlu_try_lock(rlu_data, (void **)(&left), left->size)){
                data->nr_abort++;
                return -1;
            }
        } else {
            if(!_mvrlu_try_lock(rlu_data, (void **)(&left), left->size) || !_mvrlu_try_lock(rlu_data, (void **)(&right), right->size)){
                data->nr_abort++;
                return -1;
            }
        }
    }


    if ((left->num_items + right->num_items + 1) < 
        (btree->max_items-1)) 
    {
        // merge left + item + right
        left->items[(size_t)left->num_items] = (*node)->items[(size_t)i], 
        left->num_items++;
        memcpy(left->items+sizeof(int) * left->num_items, right->items, right->num_items*sizeof(int));
        if (!left->leaf) {
            for(size_t k=0; k < right->num_items + 1; k++){
                RLU_ASSIGN_PTR(rlu_data, &(left->children[left->num_items + k]), right->children[k]);
            }
        }
        left->num_items += right->num_items;
        RLU_FREE(rlu_data, right);
        if ((*with_lock) == 0){
            if (!_mvrlu_try_lock(rlu_data, (void **)node, (*node)->size)){
                data->nr_abort++;
                return -1;
            }
            *with_lock = 1;
        }
        node_shift_left((*node), (size_t)i, 1);
    } else if (left->num_items > right->num_items) {
        // move left -> right
        node_shift_right(right, 0);
        right->items[0] = (*node)->items[(size_t)i];
        if (!left->leaf) {
            RLU_ASSIGN_PTR(rlu_data, &(right->children[0]), (left->children[left->num_items]));
        }
        if ((*with_lock) == 0){
            if (!_mvrlu_try_lock(rlu_data, (void **)node, (*node)->size)){
                data->nr_abort++;
                return -1;
            }
            *with_lock = 1;
        }
        (*node)->items[(size_t)i] = left ->items[left->num_items-1]; 
        if (!left->leaf) {
            left->children[left->num_items] = NULL;
        }
        left->num_items--;
    } else {
        // move right -> left
        left->items[left->num_items] = (*node)->items[(size_t)i];
        if (!left->leaf) {
            RLU_ASSIGN_PTR(rlu_data, &(left->children[left->num_items+1]), (right->children[0]));
        }
        left->num_items++;
        if ((*with_lock) == 0){
            if (!_mvrlu_try_lock(rlu_data, (void **)node, (*node)->size)){
                data->nr_abort++;
                return -1;
            }
            *with_lock = 1;
        }
        (*node)->items[(size_t)i] = right->items[0];
        node_shift_left(right, 0, 0);
    }
    return deleted;
}


int list_del(int key, pthread_data_t *data)
{
	rlu_btree_t *btree = (rlu_btree_t *)data->list;
	rlu_thread_data_t *rlu_data = (rlu_thread_data_t *)data->ds_data;
	node_t *prev, *cur;
	int ret, tmp, with_lock = 0;

restart:
	RLU_READER_LOCK(rlu_data);
    prev = (node_t *) RLU_DEREF(rlu_data, (btree->root));
    cur = (node_t *)RLU_DEREF(rlu_data, (prev->children[0])); 
    ret = node_delete(btree, &cur, DELKEY, 0 , key, &tmp, 0, &with_lock, data);
    if (ret == 0) {
        return 0;
    }
    else if (ret == -1){
        RLU_ABORT(rlu_data);
        goto restart; 
    }
    if (cur->num_items == 0) {
        if (!_mvrlu_try_lock(rlu_data, (void **)(&prev), prev->size)){
            data->nr_abort ++;
            RLU_ABORT(rlu_data);
            goto restart;
        }
        if (!cur->leaf) {
            RLU_ASSIGN_PTR(rlu_data, &(prev->children[0]), (cur->children[0]));
        } else {
            RLU_ASSIGN_PTR(rlu_data, &(prev->children[0]), (NULL));
        }
        RLU_FREE(rlu_data, cur);
    }
	RLU_READER_UNLOCK(rlu_data);
	return 1;
}

int list_find(int key, pthread_data_t *data)
{
	rlu_btree_t *btree = (rlu_btree_t *)data->list;
	rlu_thread_data_t *rlu_data = (rlu_thread_data_t *)data->ds_data;

	RLU_READER_LOCK(rlu_data);
    node_t *node = (node_t *)RLU_DEREF(rlu_data, (btree->root->children[0]));
    for (int depth = 0;;depth++) {
        int found = 0;
        int i = node_find(node, key, &found);
        if (found) {
	        RLU_READER_UNLOCK(rlu_data);
            return 1;
        }
        if (node->leaf) {
	        RLU_READER_UNLOCK(rlu_data);
            return 0;
        }
        node = (node_t *) RLU_DEREF(rlu_data, (node->children[i]));
    }

	RLU_READER_UNLOCK(rlu_data);

	return 0;
}