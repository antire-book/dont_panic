#include <cstdlib>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <elf.h>

/**
 * This tool implements a *very* simple cryptor. The "encryption" scheme is just
 * a one by XOR. Obviously, this isn't something you'd use to truly protect
 * a binary, but it is a interesting tool to begin to understand how cryptors
 * work.
 *
 * This tool will "encrypt" only the PF_X segment. Which means that .data is
 * left visible.
 */

/**
 * Adds the decryption stub to the end of the first PF_X segment. Rewrites the
 * entry_point address and xor "encrypts" the PF_X segment from just after the
 * program headers to the end of the segment.
 *
 * \param[in,out] p_data the ELF binary
 * \return true on success and false otherwise
 */
bool add_cryptor(std::string& p_data)
{
    if (p_data[0] != 0x7f || p_data[1] != 'E' || p_data[2] != 'L' ||
        p_data[3] != 'F')
    {
        std::cerr << "[-] Bad magic" << std::endl;
        return 0;
    }

    Elf64_Ehdr* ehdr = reinterpret_cast<Elf64_Ehdr*>(&p_data[0]);
    Elf64_Phdr* phdr = reinterpret_cast<Elf64_Phdr*>(&p_data[ehdr->e_phoff]);
    int ph_entries = ehdr->e_phnum;

    const Elf64_Phdr* segment = NULL;
    for (int i = 0; i < ph_entries && segment == NULL; i++, phdr++)
    {
        if (phdr->p_type == PT_LOAD && phdr->p_flags & PF_X)
        {
            // in order to write to the PF_X segment, we'll set the write
            // flag. However, a more elagant solution is to use mprotect
            // in the decryption stub.
            phdr->p_flags |= PF_W;
            segment = phdr;
        }
    }

    if (segment == NULL)
    {
        std::cerr << "[-] Couldn't find an executable segment." << std::endl;
        return false;
    }

    // We can't encrypt the ELF header or the program headers or we'll break the
    // loader. So begin encryption right after the program headers. This logic
    // asumes that the ELF header and the program headers fall within the
    // segment variable
    uint32_t encrypt_start = ehdr->e_phoff  + (ehdr->e_phentsize * ehdr->e_phnum);
    uint32_t virt_start = segment->p_vaddr + encrypt_start;

    // store the real offset so we can overwrite it with the stubs address.
    uint32_t actual = ehdr->e_entry;

    // this is sneaky in that *technically* speaking we'll be writing the stub
    // into address space outside of the range specified by the program header
    // BUT! In the real world, the address space is going to be page aligned
    // so as long as we can fit our stub between the end of the PF_X segment
    // and the end of the page, we are fine. We *could* just update the
    // segment to include the size of the stub, but IDA gets upset when we
    // rely on the page alignment
    ehdr->e_entry = segment->p_vaddr + segment->p_filesz;

    // this is our decryption logic. Very simple. Very small.
    unsigned char stub[] =
        "\x48\xC7\xC5\xFF\xEE\xDD\x00" // mov rbp, 0DDEEFFh <-- virt_start
        "\x49\xC7\xC1\xCC\xBB\xAA\x00" // mov r9, 0AABBCCh <-- e_entry
        "\x49\xC7\xC0\xAA\x00\x00\x00" // mov r8, 0AAh
        "\x4C\x31\x45\x00"             // xor [rbp+var_s0], r8
        "\x4C\x8B\x45\x00"             // mov r8, [rbp+var_s0]
        "\x48\xFF\xC5"                 // inc rbp
        "\x4C\x39\xCD"                 // cmp rbp, r9
        "\x7C\xE9"                     // jl  short loop
        "\x48\xC7\xC5\x19\x03\x40\x00" // mov rbp, 400319h <-- actual
        "\xFF\xE5";                    // jmp rbp

    // This is a very basic check to ensure we aren't overwriting page
    // boundaries. However, note that the value I'm using (4096) is what is good
    // for *my* system. 4096 is a very common page size but your mileage may
    // vary.
    int lower_bound = (encrypt_start + segment->p_filesz) % 4096;
    int upper_bound = (encrypt_start + segment->p_filesz + sizeof(stub)) % 4096;
    if (lower_bound > upper_bound)
    {
        std::cerr << "[-] Stub cross page boundaries" << std::endl;
        return false;
    }

    // replace the values in the assembly with real values
    memcpy(stub + 3, &virt_start, 4);
    memcpy(stub + 10, &ehdr->e_entry, 4);
    memcpy(stub + 40, &actual, 4);

    // copy the stub into the binary
    memcpy(&p_data[segment->p_filesz], stub, sizeof(stub));

    // "encrypt" the binary
    char xorValue = 0xaa;
    for (uint32_t i = encrypt_start; i < segment->p_filesz; i++)
    {
        p_data[i] ^= xorValue;
    }

    return true;
}

int main(int p_argc, char** p_argv)
{
    if (p_argc != 2)
    {
        std::cerr << "Usage: ./cryptor <file path>" << std::endl;
        return EXIT_FAILURE;
    }

    std::ifstream inputFile(p_argv[1], std::ifstream::in | std::ifstream::binary);
    if (!inputFile.is_open() || !inputFile.good())
    {
        std::cerr << "Failed to open the provided file: " << p_argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    std::string input((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    if(!add_cryptor(input))
    {
        return EXIT_FAILURE;
    }

    std::ofstream outputFile(p_argv[1], std::ofstream::out | std::ofstream::binary);
    if (!outputFile.is_open() || !outputFile.good())
    {
        std::cout << "Failed to wopen the provided file: " << p_argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    outputFile.write(input.data(), input.length());
    outputFile.close();

    return EXIT_SUCCESS;
}
