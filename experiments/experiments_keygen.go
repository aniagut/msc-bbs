package experiments

import (
    "fmt"
    "os"
    "time"
    "github.com/aniagut/msc-bbs/keygen"
    "github.com/aniagut/msc-bbs/utils"
    e "github.com/cloudflare/circl/ecc/bls12381"
)

// MeasureKeyGenTime measures the time taken for the KeyGen function
// for different numbers of users and saves the results to a file.
func MeasureKeyGenTime() {
    // Open the results file for writing
    file, err := os.Create("experiments/results/keygen_time_results.txt")
    if err != nil {
        fmt.Printf("Error creating results file: %v\n", err)
        return
    }
    defer file.Close()

    // Write the header to the file
    _, err = file.WriteString("UserCount,AverageKeyGenTime\n")
    if err != nil {
        fmt.Printf("Error writing to results file: %v\n", err)
        return
    }

    // Define the number of users to test
    userCounts := []int{10, 20, 50, 100, 500, 1000, 2000, 5000, 10000}

    // Iterate over each user count
    for _, userCount := range userCounts {
        var totalTime time.Duration

        // Run KeyGen 10 times and measure the total time
        for i := 0; i < 10; i++ {
            start := time.Now()

            // Call KeyGen
            _, err := keygen.KeyGen(userCount)
            if err != nil {
                fmt.Printf("Error during KeyGen for %d users: %v\n", userCount, err)
                return
            }

            // Measure the elapsed time
            elapsed := time.Since(start)
            totalTime += elapsed
        }

        // Calculate the average time
        averageTime := totalTime / 10

        // Print the results
        fmt.Printf("Average KeyGen time for %d users: %v\n", userCount, averageTime)

        // Write the results to the file
        _, err = file.WriteString(fmt.Sprintf("%d,%v\n", userCount, averageTime))
        if err != nil {
            fmt.Printf("Error writing to results file: %v\n", err)
            return
        }
    }
}

func MeasureSDHTuplesGenerationTimeByNumberOfUsers() {
    // Open the results file for writing
    file, err := os.Create("experiments/results/sdh_tuples_generation_time_old_results.txt")
    if err != nil {
        fmt.Printf("Error creating results file: %v\n", err)
        return
    }
    defer file.Close()

    // Write the header to the file
    _, err = file.WriteString("UserCount,AverageSDHTuplesGenerationTime\n")
    if err != nil {
        fmt.Printf("Error writing to results file: %v\n", err)
        return
    }
    // Set G1 and y
    g1 := e.G1Generator()
    y, err := utils.RandomScalar()
    if err != nil {
        fmt.Printf("Error generating random scalar: %v\n", err)
        return
    }
    // Define the number of users to test
    userCounts := []int{10, 100, 200, 500, 1000, 5000, 10000, 20000, 50000, 100000}
    // Iterate over each user count
    for _, userCount := range userCounts {
        var totalTime time.Duration

        // Run SDH Tuples generation 10 times and measure the total time
        for i := 0; i < 10; i++ {
            start := time.Now()
            // Call ComputeSDHTuples
            _, err := keygen.OldComputeSDHTuples(userCount, g1, y)
            if err != nil {
                fmt.Printf("Error during ComputeSDHTuples for %d users: %v\n", userCount, err)
                return
            }
            // Measure the elapsed time
            elapsed := time.Since(start)
            totalTime += elapsed
        }
        // Calculate the average time
        averageTime := totalTime / 10
        // Print the results
        fmt.Printf("Average SDH Tuples generation time for %d users: %v\n", userCount, averageTime)
        // Write the results to the file
        _, err = file.WriteString(fmt.Sprintf("%d,%v\n", userCount, averageTime))
        if err != nil {
            fmt.Printf("Error writing to results file: %v\n", err)
            return
        }
    }
}