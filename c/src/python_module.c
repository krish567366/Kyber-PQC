#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "kyber_pqc.h"
#include "secure.h"

static PyObject *py_keypair(PyObject *self, PyObject *Py_UNUSED(args))
{
    uint8_t public_key[KYBER_PQC_PUBLIC_KEY_BYTES];
    uint8_t private_key[KYBER_PQC_PRIVATE_KEY_BYTES];

    (void)self;
    if (kyber_pqc_keypair(public_key, private_key) != 0) {
        PyErr_SetString(PyExc_RuntimeError, "native keypair failed");
        return NULL;
    }

    return Py_BuildValue(
        "y#y#",
        public_key,
        (Py_ssize_t)KYBER_PQC_PUBLIC_KEY_BYTES,
        private_key,
        (Py_ssize_t)KYBER_PQC_PRIVATE_KEY_BYTES
    );
}

static PyObject *py_encapsulate(PyObject *self, PyObject *args)
{
    const char *public_key = NULL;
    Py_ssize_t public_key_len = 0;
    uint8_t ciphertext[KYBER_PQC_CIPHERTEXT_BYTES];
    uint8_t shared_secret[KYBER_PQC_SHARED_SECRET_BYTES];

    (void)self;
    if (!PyArg_ParseTuple(
            args,
            "y#",
            &public_key,
            &public_key_len
        )) {
        return NULL;
    }
    if (public_key_len != KYBER_PQC_PUBLIC_KEY_BYTES) {
        PyErr_SetString(PyExc_ValueError, "invalid public key length");
        return NULL;
    }
    if (kyber_pqc_encapsulate(
            (const uint8_t *)public_key,
            ciphertext,
            shared_secret
        ) != 0) {
        PyErr_SetString(PyExc_RuntimeError, "native encapsulation failed");
        return NULL;
    }

    return Py_BuildValue(
        "y#y#",
        ciphertext,
        (Py_ssize_t)KYBER_PQC_CIPHERTEXT_BYTES,
        shared_secret,
        (Py_ssize_t)KYBER_PQC_SHARED_SECRET_BYTES
    );
}

static PyObject *py_decapsulate(PyObject *self, PyObject *args)
{
    const char *ciphertext = NULL;
    const char *private_key = NULL;
    Py_ssize_t ciphertext_len = 0;
    Py_ssize_t private_key_len = 0;
    uint8_t shared_secret[KYBER_PQC_SHARED_SECRET_BYTES];
    PyObject *result = NULL;

    (void)self;
    if (!PyArg_ParseTuple(
            args,
            "y#y#",
            &ciphertext,
            &ciphertext_len,
            &private_key,
            &private_key_len
        )) {
        return NULL;
    }
    if (ciphertext_len != KYBER_PQC_CIPHERTEXT_BYTES) {
        PyErr_SetString(PyExc_ValueError, "invalid ciphertext length");
        return NULL;
    }
    if (private_key_len != KYBER_PQC_PRIVATE_KEY_BYTES) {
        PyErr_SetString(PyExc_ValueError, "invalid private key length");
        return NULL;
    }
    if (kyber_pqc_decapsulate(
            (const uint8_t *)private_key,
            (const uint8_t *)ciphertext,
            shared_secret
        ) != 0) {
        PyErr_SetString(PyExc_RuntimeError, "native decapsulation failed");
        return NULL;
    }

    result = PyBytes_FromStringAndSize(
        (const char *)shared_secret,
        (Py_ssize_t)KYBER_PQC_SHARED_SECRET_BYTES
    );
    kyber_pqc_secure_zero(shared_secret, sizeof(shared_secret));
    return result;
}

static PyObject *py_backend(PyObject *self, PyObject *Py_UNUSED(args))
{
    (void)self;
#if defined(__aarch64__) || defined(__arm64__)
    return PyUnicode_FromString("kyber-pqc-native-aarch64");
#elif defined(__AVX2__)
    return PyUnicode_FromString("kyber-pqc-native-avx2");
#else
    return PyUnicode_FromString("kyber-pqc-native-x86_64");
#endif
}

static PyMethodDef NativeMethods[] = {
    {"keypair", py_keypair, METH_NOARGS, "Generate a Kyber-512 key pair."},
    {"encapsulate", py_encapsulate, METH_VARARGS, "Encapsulate a shared secret."},
    {"decapsulate", py_decapsulate, METH_VARARGS, "Decapsulate a shared secret."},
    {"backend_name", py_backend, METH_NOARGS, "Return the active native backend."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef native_module = {
    PyModuleDef_HEAD_INIT,
    "_native",
    "Kyber-PQC native ML-KEM-512 implementation.",
    -1,
    NativeMethods
};

PyMODINIT_FUNC PyInit__native(void)
{
    return PyModule_Create(&native_module);
}
