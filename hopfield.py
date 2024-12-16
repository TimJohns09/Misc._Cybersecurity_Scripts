"""
Class that impliments the hopfield network algorithm
as a proof of concept.

Author: Tim Johns
Last Modified: 10/16/24
"""
import numpy as np

class Hopfield():

    def __init__(self, n):
        """
        Constructs an n by n hopfield network.
        """
        self._T = np.zeros((n,n))

    def learn(self, data):
        """
        Method that takes a 2D array of input patterns as a
        parameter and writes them into the hopfield network.
        """
        #Loop through array of patterns:
        for a in data:
            #Update the weights using outer product of the input pattern:
            self._T += np.outer(2 * a - 1, 2 * a - 1)
        #Remove diagonal (no self reinforcement)
        np.fill_diagonal(self._T, 0)

    def test(self, u, iterations=5):
        """
        Method that takes an array of data (u) and a number of
        iterations and runs that pattern through the hopfield
        network to reconstruct it.
        """
        for _ in range(iterations):
            u = (np.dot(u, self._T) > 0).astype(int)
        return u


def show_confusion(array1, array2):
    """
    Function that constructs and prints a confusion matrix 
    for two given arrays.
    """
    #Initialize a confusion matrix of zeroes.
    confusion_matrix = np.zeros((len(array1),len(array1)))

    #Loop through arrays, calculating the vector cosine of their corresponding vectors:
    for row in range(len(array1)):
        for col in range(len(array2)):
            #Add that value to the confusion matrix:
            confusion_matrix[row][col] = vector_cosine(array1[row],array2[col])

    #Print the formatted confusion matrix
    for i in range(len(confusion_matrix)):
        for j in range(i + 1):
            # Print the cosine value with two decimal places
            print(f"{confusion_matrix[i][j]:.2f}", end=" ")
        print()

def noisy_copy(array, probability):
    """
    Function that creates a noisy copy of an array 
    based on a given probability.
    Returns: The noisy array:
    """
    #Create a new array to contain the noisy data:
    noisy_array = np.copy(array)
    #Loop through the array:
    for row in range(len(noisy_array)):
        for col in range(len(noisy_array[row])):
            #Generate random number and execute if within random boundary:
            if np.random.rand() < probability:
                #Flip the bit:
                noisy_array[row][col] = 1 - noisy_array[row][col]
    return noisy_array


def vector_cosine(vector1, vector2):
    """
    Function that returns the vector cosine
    similiarity between two vectors.
    """
    #Get the dotproduct
    dot_product = np.dot(vector1, vector2)
    #Get the product of (sqrt A)^2 and (sqrt B)^2
    vector1Squared = np.sqrt(np.sum(vector1 ** 2))
    vector2Squared = np.sqrt(np.sum(vector2 ** 2))
    #Compute vector cosine by dividing the dotproduct by the product of (sqrt A)^2 and (sqrt B)^2
    vector_cosine = dot_product / (vector1Squared * vector2Squared)
    return vector_cosine


def main():

    print("\nPart 2: Vector-cosine confusion matrix of an array with itself ----------------------")
    input_vector = np.random.randint(2, size=(5, 30))
    show_confusion(input_vector, input_vector)


    print("\n\nPart 3: Confusion matrix with 25 percent noise ------------------------------------")
    noisy_vector = noisy_copy(input_vector, 0.25)
    show_confusion(input_vector, noisy_vector)


    print("\n\nPart 4: Recovering small patterns with a Hopfield net -----------------------------")
    #Initialize Network:
    hopNet = Hopfield(30)
    #Train network on randomized input vector pattern:
    hopNet.learn(input_vector)
    inp = input_vector[0]
    outp = hopNet.test(inp)
    #Print test the network on one of the patterns in the set:
    print("Recover pattern, no noise:")
    print("Input:\t", inp)
    print("Output:\t", outp)
    print("Vector Cosine:\t", round(vector_cosine(inp, outp), 2))
    
    #Get a pattern from the noisy set:
    input = noisy_vector[0]
    #Test it in the hopfield net:
    output = hopNet.test(input)
    #Print results:
    print("\n\nRecover pattern, 25% noise:")
    print("Input:\t ", input)
    print("Output:\t ", output)
    print("Original:", input_vector[0])
    print("Vector Cosine:\t", round(vector_cosine(output, input_vector[0]),2))
    

    print("\n\nPart 5: Recovering big patterns ----------------------------------------------------")
    print("\nConfusion matrix for 1000-element vectors with 25 percent noise:")
    #Create a 10x10000 input vector:
    input_vector = np.random.randint(2, size=(10, 10000))
    #Create a new hopfield network and let it learn the new input data:
    hopNet = Hopfield(10000)
    hopNet.learn(input_vector)
    #Create a noisy copy of the new input data and show the confusion matrix:
    noisy_vector = noisy_copy(input_vector, 0.25)
    show_confusion(input_vector, noisy_vector)

    print("\nRecovering patterns with 25 percent noise:\n")
    #Loop through the patterns in the input vector:
    for i in range(len(input_vector)):
        #Generate the input:
        input = input_vector[i]
        #Test the hopfield network on the new input:
        output = hopNet.test(input)
        #Print the vector cosine of the original:
        print(f"Vector cosine on pattern {i} = {vector_cosine(output, input_vector[i]):.2f}")



if __name__ == '__main__':
    main()
