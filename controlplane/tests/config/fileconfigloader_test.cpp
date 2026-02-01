#include <gtest/gtest.h>
#include <fstream>
#include <filesystem>
#include "fileconfigloader.h"

class FileConfigLoaderTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_filename = "file.txt";
        std::ofstream file(test_filename);
        file << "Test content";
        file.close();
    }
    
    void TearDown() override {
        if (std::filesystem::exists(test_filename)) {
            std::filesystem::remove(test_filename);
        }
    }
    
    std::string test_filename;
};

TEST_F(FileConfigLoaderTest, OpenExistingFile) {
    blncr::loader::FileConfigLoader loader{test_filename};
    ASSERT_TRUE(loader.openFile());
}

TEST_F(FileConfigLoaderTest, OpenNonExistingFile) {
    blncr::loader::FileConfigLoader loader{"f.txt"};
    ASSERT_FALSE(loader.openFile());
}

TEST_F(FileConfigLoaderTest, ReadNonEmptyFile) {
    blncr::loader::FileConfigLoader loader{test_filename};
    ASSERT_TRUE(loader.openFile());
    auto data = loader.LoadConfig();
    ASSERT_EQ(data, std::string{"Test content"});
}

TEST_F(FileConfigLoaderTest, ReadNonExistingFile) {
    blncr::loader::FileConfigLoader loader{"f.txt"};
    ASSERT_FALSE(loader.openFile());
    auto data =  loader.LoadConfig();
    ASSERT_TRUE(data.empty());
}