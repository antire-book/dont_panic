#include <cstdlib>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <random>
#include <elf.h>
#include <map>

#include "rc4.h"

/**
 * This tool will search through a binaries section table and look for
 * specially named section. Specifically, any section whose name that starts
 * with ".rc4_*" will be marked as a location to store a 128 byte key and the
 * section named by the "*" in ".rc4_*" will be encrypted using rc4.
 */

/**
 * This function finds the special ".rc4_" section, generates a key, and
 * encrypts the specified section.
 *
 * \param[in,out] p_data the ELF binary
 * \return true on success and false otherwise
 */
bool encrypt_functions(std::string& p_data)
{
    if (p_data[0] != 0x7f || p_data[1] != 'E' || p_data[2] != 'L' || p_data[3] != 'F')
    {
        return false;
    }

    Elf64_Ehdr* ehdr = reinterpret_cast<Elf64_Ehdr*>(&p_data[0]);
    Elf64_Shdr* sections = reinterpret_cast<Elf64_Shdr*>(&p_data[ehdr->e_shoff]);
    Elf64_Half sections_count = ehdr->e_shnum;
    Elf64_Shdr* strings_header = reinterpret_cast<Elf64_Shdr*>(&p_data[ehdr->e_shoff] +
        (ehdr->e_shentsize * ehdr->e_shstrndx));
    const char* strings_table = &p_data[strings_header->sh_offset];

    std::map<std::string, Elf64_Addr> encrypt_mappings;

    // find all ".rc4_" sections.
    Elf64_Shdr* current = sections;
    for (int i = 0; i < sections_count; i++, current++)
    {
        std::string section_name(&strings_table[current->sh_name]);
        if (section_name.find(".rc4_") == 0)
        {
            // store the other half of the section name to find where to encrypt
            std::string func_name = "." + section_name.substr(5);
            encrypt_mappings[func_name] = current->sh_offset;
        }
    }

    // find all sections that ".rc4_*" was referencing for encryption
    current = sections;
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 255);
    for (int i = 0; i < sections_count; i++, current++)
    {
        std::string section_name(&strings_table[current->sh_name]);
        if (encrypt_mappings.find(section_name) != encrypt_mappings.end())
        {
            // randomly generate a key to encrypt with
            unsigned char key[128] = { 0 };
            for (std::size_t i = 0; i < sizeof(key); i++)
            {
                key[i] = dist(rd);
            }

            // encrypt the section
            struct rc4_state state = {};
            rc4_init(&state, key, sizeof(key));
            rc4_crypt(&state, reinterpret_cast<unsigned char*>(&p_data[current->sh_offset]),
                      reinterpret_cast<unsigned char*>(&p_data[current->sh_offset]),
                      current->sh_size);
            memcpy(&p_data[encrypt_mappings[section_name]], key, sizeof(key));
        }
    }

    return true;
}

int main(int p_argc, char** p_argv)
{
    if (p_argc != 2)
    {
        std::cerr << "Usage: ./encryptFunctions <file path>" << std::endl;
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

    if (!encrypt_functions(input))
    {
        std::cerr << "Failed to complete the encryption function" << std::endl;
        return EXIT_FAILURE;
    }

    std::ofstream outputFile(p_argv[1], std::ofstream::out | std::ofstream::binary);
    if (!outputFile.is_open() || !outputFile.good())
    {
        std::cerr << "Failed to wopen the provided file: " << p_argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    outputFile.write(input.data(), input.length());
    outputFile.close();

    return EXIT_SUCCESS;
}
