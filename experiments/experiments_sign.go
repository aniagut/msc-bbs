package experiments

import (
    "fmt"
    "time"
    "os"
    "github.com/aniagut/msc-bbs/keygen"
    "github.com/aniagut/msc-bbs/sign"
)


// MeasureSignTime measures the time taken for the Sign function
// for different size of the messages

func MeasureSignTime() {
    // Open the results file for writing
    file, err := os.Create("experiments/results/sign_time_results.txt")
    if err != nil {
        fmt.Printf("Error creating results file: %v\n", err)
        return
    }
    defer file.Close()

    // Write the header to the file
    _, err = file.WriteString("MessageLength,AverageSignTime\n")
    if err != nil {
        fmt.Printf("Error writing to results file: %v\n", err)
        return
    }

    // Generate keys for the system with one user
    keyGenResult, err := keygen.KeyGen(1)
    if err != nil {
        fmt.Printf("Error during KeyGen: %v\n", err)
        return
    }
    // Extract the public key and user key from the result
    publicKey, userKey := keyGenResult.PublicKey, keyGenResult.Users[0]

    // Define the length of the message string to test
    messageLengths := []int{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000}
    // Iterate over each message length
    for _, length := range messageLengths {
        // Create a random message of the specified length
        message := make([]byte, length)
        for i := range message {
            message[i] = 'a' + byte(i%26) // Fill with letters a-z
        }
        messageString := string(message)
        var totalTime time.Duration
        // Run Sign 10 times and measure the total time
        for i := 0; i < 10; i++ {
            start := time.Now()
            // Call Sign
            _, err := sign.Sign(publicKey, userKey, messageString)
            if err != nil {
                fmt.Printf("Error during Sign for length=%d: %v\n", length, err)
                return
            }
            // Measure the elapsed time
            elapsed := time.Since(start)
            totalTime += elapsed
        }
        // Calculate the average time
        averageTime := totalTime / 10

        // Print the results
        fmt.Printf("Average Sign time for message length=%d: %v\n", length, averageTime)

        // Write the results to the file
        _, err = file.WriteString(fmt.Sprintf("%d,%v\n", length, averageTime))
        if err != nil {
            fmt.Printf("Error writing to results file: %v\n", err)
            return
        }
    }
}