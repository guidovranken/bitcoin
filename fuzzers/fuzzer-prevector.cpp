#include "fuzzer.h"
#include "prevector.h"

/* Copied from src/test/prevector_tests.cpp.
 * However, in this version, running test() after each operation is optional.
 *
 * Because test() makes the process very slow, by disabling it you can
 * generate a fuzzer corpus quickly.
 *
 * Once a large corpus has been generated, you can enable test() and run
 * the inputs again.
 */


template<unsigned int N, typename T>
class prevector_tester {
    typedef std::vector<T> realtype;
    realtype real_vector;
    realtype real_vector_alt;

#ifndef SIZETYPE_UINT16_T
    typedef prevector<N, T> pretype;
#else
    typedef prevector<N, T, uint16_t> pretype;
#endif
    pretype pre_vector;
    pretype pre_vector_alt;

    typedef typename pretype::size_type Size;
    bool passed = true;
    bool run_test;


    template <typename A, typename B>
        void local_check_equal(A a, B b)
        {
            local_check(a == b);
        }
    void local_check(bool b) 
    {
        passed &= b;
    }
    void test() {
        if ( run_test == false ) {
            return;
        }

        const pretype& const_pre_vector = pre_vector;
        local_check_equal(real_vector.size(), pre_vector.size());
        local_check_equal(real_vector.empty(), pre_vector.empty());
        for (Size s = 0; s < real_vector.size(); s++) {
             local_check(real_vector[s] == pre_vector[s]);
             local_check(&(pre_vector[s]) == &(pre_vector.begin()[s]));
             local_check(&(pre_vector[s]) == &*(pre_vector.begin() + s));
             local_check(&(pre_vector[s]) == &*((pre_vector.end() + s) - real_vector.size()));
        }
        // local_check(realtype(pre_vector) == real_vector);
        local_check(pretype(real_vector.begin(), real_vector.end()) == pre_vector);
        local_check(pretype(pre_vector.begin(), pre_vector.end()) == pre_vector);
        size_t pos = 0;
        BOOST_FOREACH(const T& v, pre_vector) {
             local_check(v == real_vector[pos++]);
        }
        BOOST_REVERSE_FOREACH(const T& v, pre_vector) {
             local_check(v == real_vector[--pos]);
        }
        BOOST_FOREACH(const T& v, const_pre_vector) {
             local_check(v == real_vector[pos++]);
        }
        BOOST_REVERSE_FOREACH(const T& v, const_pre_vector) {
             local_check(v == real_vector[--pos]);
        }
#ifndef SIZETYPE_UINT16_T
        CDataStream ss1(SER_DISK, 0);
        CDataStream ss2(SER_DISK, 0);
        ss1 << real_vector;
        ss2 << pre_vector;
        local_check_equal(ss1.size(), ss2.size());
        for (Size s = 0; s < ss1.size(); s++) {
            local_check_equal(ss1[s], ss2[s]);
        }
#endif
    }

public:
    void resize(Size s) {
        real_vector.resize(s);
        local_check_equal(real_vector.size(), s);
        pre_vector.resize(s);
        local_check_equal(pre_vector.size(), s);
        test();
    }

    void reserve(Size s) {
        real_vector.reserve(s);
        local_check(real_vector.capacity() >= s);
        pre_vector.reserve(s);
        local_check(pre_vector.capacity() >= s);
        test();
    }

    void insert(Size position, const T& value) {
        real_vector.insert(real_vector.begin() + position, value);
        pre_vector.insert(pre_vector.begin() + position, value);
        test();
    }

    void insert(Size position, Size count, const T& value) {
        real_vector.insert(real_vector.begin() + position, count, value);
        pre_vector.insert(pre_vector.begin() + position, count, value);
        test();
    }

    template<typename I>
    void insert_range(Size position, I first, I last) {
        real_vector.insert(real_vector.begin() + position, first, last);
        pre_vector.insert(pre_vector.begin() + position, first, last);
        test();
    }

    void erase(Size position) {
        real_vector.erase(real_vector.begin() + position);
        pre_vector.erase(pre_vector.begin() + position);
        test();
    }

    void erase(Size first, Size last) {
        real_vector.erase(real_vector.begin() + first, real_vector.begin() + last);
        pre_vector.erase(pre_vector.begin() + first, pre_vector.begin() + last);
        test();
    }

    void update(Size pos, const T& value) {
        real_vector[pos] = value;
        pre_vector[pos] = value;
        test();
    }

    void push_back(const T& value) {
        real_vector.push_back(value);
        pre_vector.push_back(value);
        test();
    }

    void pop_back() {
        real_vector.pop_back();
        pre_vector.pop_back();
        test();
    }

    void clear() {
        real_vector.clear();
        pre_vector.clear();
    }

    void assign(Size n, const T& value) {
        real_vector.assign(n, value);
        pre_vector.assign(n, value);
    }

    Size size() {
        return real_vector.size();
    }

    Size capacity() {
        return pre_vector.capacity();
    }

    void shrink_to_fit() {
        pre_vector.shrink_to_fit();
        test();
    }

    void swap() {
        real_vector.swap(real_vector_alt);
        pre_vector.swap(pre_vector_alt);
        test();
    }

    void move() {
        real_vector = std::move(real_vector_alt);
        real_vector_alt.clear();
        pre_vector = std::move(pre_vector_alt);
        pre_vector_alt.clear();
    }

    void copy() {
        real_vector = real_vector_alt;
        pre_vector = pre_vector_alt;
    }

    ~prevector_tester() {
        if ( passed == false ) {
            /* Test failed, abort fuzzing, print backtrace */
            abort();
        }
    }
    prevector_tester(bool rt) {
        run_test = rt;
    }
};

enum TEST_ID {
    PREVECTOR_RESIZE=0,
    PREVECTOR_INSERT,
    PREVECTOR_ERASE,
    PREVECTOR_PUSH_BACK,
    PREVECTOR_POP_BACK,
    PREVECTOR_INSERT_RANGE,
    PREVECTOR_RESERVE,
    PREVECTOR_SHRINK_TO_FIT,
    PREVECTOR_UPDATE,
    PREVECTOR_CLEAR,
    PREVECTOR_ASSIGN,
    PREVECTOR_SWAP,
    PREVECTOR_COPY,
    PREVECTOR_MOVE,
    TEST_ID_END
};

template <typename T>
class prevector_fuzzer
{
    public:
        prevector_fuzzer(bool run_test) {
            test = new prevector_tester<1, T>(run_test);
        }
        ~prevector_fuzzer() {
        }

        void setState(const uint8_t* d, size_t s, size_t m) {
            data = d;
            size = s;
            m = mask;
        }

        void run(void) {
            try {
                /* Once it is out of data, an exception is thrown */
                while ( true ) {
                    iter();
                }
            } catch ( const std::runtime_error& e ) {
            }
        }

    private:
        const uint8_t* data;
        size_t size, mask;
        prevector_tester<1,T>* test;

        void iter(void) {
            uint8_t choice = get_byte();

            if ( choice >= TEST_ID_END ) {
                return;
            }

            switch ( choice ) {
                case PREVECTOR_RESIZE:
                    {
                        uint16_t s = get_short(true);

                        test->resize(s);
                    }
                    break;
                case PREVECTOR_INSERT:
                    {
                        uint16_t s = get_short(true);
                        T item = get_item();

                        test->insert(s % (test->size()+1), item);
                    }
                    break;
                case PREVECTOR_ERASE:
                    {
                        if ( test->size() > 0 ) {
                            uint8_t byte = get_byte();
                            uint16_t beg = get_short(true);
                            uint32_t del = std::min<uint32_t>(test->size(), 1 + (byte));

                            beg %= (test->size() + 1 - del);

                            test->erase(beg);
                        }
                    }
                    break;
                case PREVECTOR_PUSH_BACK:
                    {
                        uint8_t byte = get_byte();

                        test->push_back( byte );
                    }
                    break;
                case PREVECTOR_POP_BACK:
                    {
                        if ( test->size() > 0 ) {
                            test->pop_back();
                        }
                    }
                    break;
                case PREVECTOR_INSERT_RANGE:
                    {
                        uint8_t num_insert = get_byte();
                        uint16_t pos = get_short(true);

                        pos %= (test->size() + 1);

                        if ( can_advance(num_insert) ) {
                            test->insert_range(pos, data, data + num_insert);
                            advance(num_insert);
                        }
                    }
                    break;
                case PREVECTOR_RESERVE:
                    {
                        uint16_t num = get_short(true);

                        test->reserve(num);
                    }
                case PREVECTOR_SHRINK_TO_FIT:
                    {
                        test->shrink_to_fit();
                    }
                    break;
                case PREVECTOR_UPDATE:
                    if ( test->size() )
                    {
                        if (test->size() > 0) {
                            uint16_t pos = get_short(true);
                            pos %= (test->size() + 1);

                            T item = get_item();

                            test->update(pos % (test->size()), item);
                        }
                    }
                    break;
                case PREVECTOR_CLEAR:
                    {
                        test->clear();
                    }
                    break;
                case PREVECTOR_ASSIGN:
                    if ( test->size() )
                    {
                        uint16_t pos = get_short(true);
                        pos %= (test->size() + 1);

                        T item = get_item();

                        test->assign(pos % (test->size()), item);
                    }
                    break;
                case PREVECTOR_SWAP:
                    {
                        test->swap();
                    }
                    break;
                case PREVECTOR_COPY:
                    {
                        test->copy();
                    }
                    break;
                case PREVECTOR_MOVE:
                    {
                        test->move();
                    }
            }
        }

        uint8_t get_byte(void) {
            uint8_t b;
            get_data(&b, sizeof(b));
            return b;
        }

        uint16_t get_short(void) {
#ifndef SIZETYPE_UINT16_T
            uint16_t s;
#else
            uint8_t s;
#endif
            get_data(&s, sizeof(s));
            return s;
        }

        uint16_t get_short(bool masked) {
#ifndef SIZETYPE_UINT16_T
            uint16_t s;
#else
            uint8_t s;
#endif
            get_data(&s, sizeof(s));

            if ( masked ) {
                s &= mask;
            }

            return s;
        }

        T get_item(void) {
            T t;
            get_data(&t, sizeof(t));
            return t;
        }

        void get_data(void* to, size_t s) {
            if ( can_advance(s) ) {
                memcpy(to, data, s);
                advance(s);
            }
        }

        bool can_advance(size_t s) {
            if ( s > size ) {

                /* Out of data -- terminate this run */
                throw std::runtime_error("");
            }

            return true;
        }

        void advance(size_t s) {
            data += s;
            size -= s;
        }
};

prevector_fuzzer<uint8_t>* pf;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    pf = new prevector_fuzzer<uint8_t>(true);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    pf->setState(data, size, 0xFFF);
    pf->run();
    return 0;
}
