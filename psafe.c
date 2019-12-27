#include <errno.h>
#include <fcntl.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define MESSAGE_LEN 1024
#define CIPHERTEXT_LEN (crypto_secretbox_MACBYTES + MESSAGE_LEN)

uint32_t reliable_read (int fd, uint8_t* buff, uint32_t num_bytes)
{
    int read_bytes = 0;
    int remain_bytes = num_bytes;
    uint32_t retval = EXIT_FAILURE;

    if (-1 == fd)
    {
        printf("Bad file descriptor\n");
        goto fd_error;
    }

    if (NULL == buff)
    {
        printf("NULL == buff\n");
        goto buff_error;
    }

    if (0 >= num_bytes)
    {
        printf("0 >= num_bytes\n");
        goto num_bytes_error;
    }

    while (0 < remain_bytes)
    {
        errno = 0;
        read_bytes = read(fd, buff + num_bytes - remain_bytes, remain_bytes);
        /* If read is interrupted by a signal, we should simply try again */
        if (-1 == read_bytes && EINTR == errno)
        {
            continue;
        }
        /* If read is interrupted for any other reasons, this is critical and we should stop */
        else if (-1 == read_bytes && EINTR != errno)
        {
            printf("Failed to read - %s\n", strerror(errno));
            goto read_error;
        }
        remain_bytes = remain_bytes - read_bytes;
    }

    /* If the program gets this far, it's assumed to have succeeded */
    retval = EXIT_SUCCESS;
    goto end_success;

read_error:
num_bytes_error:
buff_error:
fd_error:
end_success:
    return retval;
}

uint32_t reliable_write (int fd, uint8_t* buff, uint32_t num_bytes)
{
    int sent_bytes = 0;
    int remain_bytes = num_bytes;
    uint32_t retval = EXIT_FAILURE;

    if (-1 == fd)
    {
        printf("Bad file descriptor\n");
        goto fd_error;
    }

    if (NULL == buff)
    {
        printf("NULL == buff\n");
        goto buff_error;
    }

    if (0 >= num_bytes)
    {
        printf("0 >= num_bytes\n");
        goto num_bytes_error;
    }

    while (0 < remain_bytes)
    {
        errno = 0;
        sent_bytes = write(fd, buff + num_bytes - remain_bytes, remain_bytes);
        /* If write is interrupted by a signal, we should simply try again */
        if (-1 == sent_bytes && EINTR == errno)
        {
            continue;
        }
        /* If write is interrupted for any other reasons, this is critical and we should stop */
        else if (-1 == sent_bytes && EINTR != errno)
        {
            printf("Failed to write - %s\n", strerror(errno));
            goto write_error;
        }
        remain_bytes = remain_bytes - sent_bytes;
    }

    /* If the program gets this far, it's assumed to have succeeded */
    retval = EXIT_SUCCESS;
    goto end_success;

write_error:
num_bytes_error:
buff_error:
fd_error:
end_success:
    return retval;
}

uint32_t read_file (char* filename, char* buff, uint32_t len)
{
    int fd = -1;
    mode_t mode = 0440;
    struct stat stat_buff;
    uint32_t retval = EXIT_FAILURE;

    if (NULL == filename)
    {
        printf("NULL == filename\n");
        goto filename_error;
    }

    if (NULL == buff)
    {
        printf("NULL == buff\n");
        goto buff_error;
    }

    fd = open(filename, O_RDONLY, mode);
    if (-1 == fd)
    {
        printf("Failed to open\n");
        goto open_error;
    }

    memset(&stat_buff, 0, sizeof(struct stat));
    if (-1 == stat(filename, &stat_buff)) 
    {
        printf("Failed to stat\n");
        goto stat_error;
    }

    if (stat_buff.st_size > len)
    {
        printf("Insufficiently small buffer\n");
        goto len_error;
    }

    if (EXIT_SUCCESS != reliable_read(fd, buff, stat_buff.st_size))
    {
        printf("Failed to reliable_read\n");
        goto reliable_read_error;
    }

    close(fd);
    fd = -1;

    /* If the program gets this far, it's assumed to have succeeded */
    retval = EXIT_SUCCESS;
    goto end_success;

reliable_read_error:
len_error:
stat_error:
    close(fd);
    fd = -1;
open_error:
buff_error:
filename_error:
end_success:
    return retval;
}

uint32_t write_file (char* filename, char* buff, uint32_t len)
{
    int fd = -1;
    mode_t mode = 0220;
    uint32_t retval = EXIT_FAILURE;

    if (NULL == filename)
    {
        printf("NULL == filename\n");
        goto filename_error;
    }

    if (NULL == buff)
    {
        printf("NULL == buff\n");
        goto buff_error;
    }

    fd = open(filename, O_CREAT | O_WRONLY, mode);
    if (-1 == fd)
    {
        printf("Failed to open\n");
        goto open_error;
    }

    if (EXIT_SUCCESS != reliable_write(fd, buff, len))
    {
        printf("Failed to reliable_write\n");
        goto reliable_write_error;
    }

    close(fd);
    fd = -1;

    /* If the program gets this far, it's assumed to have succeeded */
    retval = EXIT_SUCCESS;
    goto end_success;

reliable_write_error:
len_error:
stat_error:
    close(fd);
    fd = -1;
open_error:
buff_error:
filename_error:
end_success:
    return retval;
}

int main (int argc, const char* argv[])
{
    uint32_t retval = EXIT_FAILURE;
    uint8_t key[crypto_secretbox_KEYBYTES];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    uint8_t decrypted[MESSAGE_LEN];
    uint8_t ciphertext[CIPHERTEXT_LEN];
    uint8_t message[CIPHERTEXT_LEN];

    if (0 > sodium_init())
    {
        printf("Error initializing sodium\n");
        goto sodium_init_error;
    }

    memset(ciphertext, 0, CIPHERTEXT_LEN);
    strncpy(key, argv[2], crypto_secretbox_KEYBYTES);
    if (EXIT_SUCCESS != read_file((char*)argv[1], ciphertext, CIPHERTEXT_LEN))
    {
        printf("Failed to read_file\n");
        goto read_file_error;
    }
    strncpy(message, ciphertext, MESSAGE_LEN);

    crypto_secretbox_keygen(key);
    randombytes_buf(nonce, sizeof nonce);
    printf("%s\n", ciphertext);
    crypto_secretbox_easy(ciphertext, message, MESSAGE_LEN, nonce, key);
    printf("%s\n", ciphertext);


    if (crypto_secretbox_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce, key) != 0) 
    {
        printf("Message forged!\n");
        goto crypto_secretbox_open_easy_error;
    }
    printf("%s\n", decrypted);
    if (EXIT_SUCCESS != write_file((char*)argv[3], decrypted, MESSAGE_LEN))
    {
        printf("Failed to write_file\n");
        goto write_file_error;
    }

    /* If the program gets this far, it's assumed to have succeeded */
    retval = EXIT_SUCCESS;
    goto end_success;

write_file_error:
crypto_secretbox_open_easy_error:
read_file_error:
sodium_init_error:
end_success:
    return retval;
}

