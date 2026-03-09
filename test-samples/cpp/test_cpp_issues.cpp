/**
 * Test: C++ Specific Vulnerabilities
 * Expected detections: new/delete, exception safety, smart pointer misuse,
 *                      reinterpret_cast, off-by-one, array OOB, pragmas
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>
#include <string>

#pragma pack(1)  // PRAGMA PACK: alignment modification
#pragma warning(disable: 4996)  // WARNING SUPPRESSED

#define _FORTIFY_SOURCE 0  // FORTIFY DISABLED

/* ---- new without delete ---- */

void new_without_delete() {
    int *arr = new int[1000];
    arr[0] = 42;
    // MEMORY LEAK: no delete[]
}

/* ---- delete without virtual destructor ---- */

class Base {
public:
    // No virtual destructor!
    void doSomething() { printf("base\n"); }
};

class Derived : public Base {
    int *data;
public:
    Derived() { data = new int[100]; }
    ~Derived() { delete[] data; }
};

void delete_without_virtual_dtor() {
    Base *ptr = new Derived();
    delete ptr;  // Missing virtual destructor: Derived::~Derived not called
}

/* ---- Exception Safety ---- */

class UnsafeResource {
    int *buffer1;
    int *buffer2;
public:
    UnsafeResource() {
        buffer1 = new int[100];   // RAW NEW in constructor
        buffer2 = new int[200];   // If this throws, buffer1 leaks
    }
    ~UnsafeResource() {
        delete[] buffer1;
        delete[] buffer2;
    }
};

/* ---- Smart Pointer Misuse ---- */

class Node {
    std::shared_ptr<Node> parent;  // SHARED_PTR CYCLE: should be weak_ptr
    std::shared_ptr<Node> child;
public:
    void setChild(std::shared_ptr<Node> c) {
        child = c;
        c->parent = std::shared_ptr<Node>(this);  // Cycle + raw this in shared_ptr
    }
};

void inefficient_shared_ptr() {
    std::shared_ptr<int> p = std::shared_ptr<int>(new int(42));  // Use make_shared
}

/* ---- Type Confusion ---- */

void type_confusion_reinterpret() {
    int x = 42;
    float *fp = reinterpret_cast<float*>(&x);  // DANGEROUS reinterpret_cast
    printf("Value: %f\n", *fp);
}

/* ---- Off-by-One ---- */

void off_by_one_loop() {
    char buffer[10];
    int len = sizeof(buffer);
    for (int i = 0; i <= len; i++) {  // OFF-BY-ONE: should be < len
        buffer[i] = 'A';
    }
    buffer[9] = '\0';
}

void off_by_one_size() {
    int count = 100;
    for (int i = 0; i <= count; i++) {  // OFF-BY-ONE with count
        printf("%d ", i);
    }
}

/* ---- Array Out of Bounds ---- */

void array_oob() {
    int arr[10];
    arr[10] = 42;  // OUT OF BOUNDS: index 10, size 10
    arr[15] = 99;  // OUT OF BOUNDS: index 15, size 10
}

/* ---- Return Pointer to Local ---- */

int *return_stack_pointer() {
    int local_value = 100;
    return &local_value;  // DANGLING POINTER: returning local address
}

char *return_local_array() {
    char buffer[256];
    strcpy(buffer, "hello world");
    return buffer;  // DANGLING: buffer is stack-allocated (technically same issue)
}

/* ---- Overlapping memcpy ---- */

void overlapping_copy() {
    char buffer[100];
    memcpy(buffer + 10, buffer, 50);  // OVERLAPPING: should use memmove
    memcpy(buffer, buffer, 100);      // OVERLAPPING: same src/dst
}

/* ---- Integer Overflow in allocation ---- */

void integer_overflow_alloc(size_t count) {
    int *data = (int *)malloc(count * sizeof(int));  // INTEGER OVERFLOW
    if (data) {
        data[0] = 1;
        free(data);
    }
}

/* ---- Uninitialized Variable ---- */

int use_uninitialized() {
    int result;
    int flag;
    if (flag) {     // UNINITIALIZED: flag used before assignment
        result = 1;
    }
    return result;  // UNINITIALIZED: result may not be set
}

int main() {
    new_without_delete();
    delete_without_virtual_dtor();
    off_by_one_loop();
    array_oob();
    overlapping_copy();
    integer_overflow_alloc(1000);
    use_uninitialized();
    return 0;
}
