"""
This is a proof-of-concept program that uses a Sparse Distributed Memory
to conceal potentially malicious files. It works by reading in one or more malicious
files, breaking them into chunks, and storing those chunks in a sparse distributed memory, 
which consists of a mapping of logical memory addresses to data locations. Once all files
are stored in the sdm, the memory adresses, data, keys, and retrieval function are stored in a 
new file called 'neuro_loader.py'. In theory, traditional antivirus detection engines
should not be able to discern that this loader file contains one or more embeded malicious
files because it does not pack or encode the files in a manner that is typical of malware programs. 

After the sdm is trained to remember the malicious files, the neuro loader file could, 
in theory, be planted on a victim machine, and, depending on how the attacker wanted to trigger the 
retrieval machanism, reconstruct the malicious file on the victim's host without having to download
the files from the internet.

This is merely a preliminary proof-of-concept. It has a number of problems, the two most notable
of which being the large size of the 'neuro_loader.py' file, and the means by which the reconstruction
is eventually triggered. More comprehensive, optimized and usable versions are in development.

Author: Tim Johns
Last Modified: 12/18/24
"""
import numpy as np

class SDM:

    def __init__(self, p, n):
        """
        Constructor that initializes the SDM with random addresses and zeroed data storage.
        """
        #Initialize the number of addresses:
        self.p = p
        #Initialize length of addresses:
        self.n = n
        #Initialize array of random addresses:
        self.addresses = np.random.randint(0, 2, (p, n))
        #Initialize array of data storage with zeros:
        self.data = np.zeros((p, n))
        #Initialize value for the radius:
        self.radius = 0.451 * n

    def enter(self, addressVector):
        """
        This method 'enters' the info in an address vector into the sdm's data array
        by finding all the addresses within the radius of the given address vector, and then writing 
        the given address's info to the physical address's data by adding or subtracting 1
        based on the value in the addressVector.
        """
        #Loop through the sdm's array of addresses:
        for i in range(self.p):

            #Compute the Hamming distance between the address vector and the current physical address:
            hdist = hamming_distance(self.addresses[i], addressVector)

            #Check if the Hamming distance is within the radius:
            if hdist <= self.radius:
                #Update the data vector at this physical address by looping through its bits:
                for j in range(self.n):
                    if addressVector[j] == 1:
                        #If the bit in the address vector is 1, add 1 to the data vector:
                        self.data[i][j] += 1
                    else:
                        #If the bit in the address vector is 0, subtract 1 from the data vector:
                        self.data[i][j] -= 1


    def lookup(self, addressVector):
        """
        This method 'looks up' the information stored in the data vector
        of the sdm finding all the addresses within the neighborhood of the
        given address vector, and then adding each bit in the data to the retrieved data vector.
        The information stored in that retrieved vector is then converted to 
        ones and zeros for output.
        """
        #Initialze array of 0s for retrieved data:
        retrieved_data = np.zeros(self.n)

        #Loop through the addresses:
        for i in range(self.p):

            #Compute the Hamming distance between the address vector and the current physical address:
            hdist = hamming_distance(self.addresses[i], addressVector)

            #Check if the Hamming distance is within the radius:
            if hdist <= self.radius:
                #If within the neighborhood, add the data at the current address to our retrieved data vector:
                for j in range(self.n):
                    retrieved_data[j] += self.data[i][j]

        #Convert the retrieved data to ones and zeros:
        for j in range(self.n):
            #If positive set to 1
            if retrieved_data[j] >= 0:
                retrieved_data[j] = 1
            #If negative set to zero:
            else:
                retrieved_data[j] = 0

        return retrieved_data
    

    def learn(self, iterations, probability):
        """
        This method enters a specified number of noisy rings into
        the sdm. Each ring is as noisy as is specified by the
        probability parameter.
        """
        #Enter a pattern for each desired iteration:
        for x in range(iterations):
            #Get a noisy ring:
            data = noisy_copy(ring(), probability)
            plot(data, 16)
            print()
            #Enter the ring into the sdm:
            self.enter(data)


    def test(self, noisyArray):
        """
        This method tests the sdm by returning the array
        that is produced by looking up a given noisy
        array.
        """
        return self.lookup(noisyArray)



#-----------------------FUNCTIONS-----------------------

def plot(array, numColumns):
    """
    This function plots the points stored in an array by 
    priting them for a given number of columns.
    """
    #Initialize counter to count columns.
    count = 0
    #Loop through the array, printing the necessary character:
    for i in range(len(array)):
        if array[i] == 1:
            print("*", end=" ")
        else:
            print(" ", end=" ")
        #Incriment count:
        count += 1
        #If count gets to 16, print a newline and reset the counter:
        if count == numColumns:
            print()
            count = 0
        


def ring():
    """
    This function returns a hardcoded array containing 1's and 0's in
    the shape of a ring.
    """
    return np.asarray([
        0,0,0,0,0,1,1,1,1,1,1,0,0,0,0,0,
        0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,
        0,0,1,1,1,1,0,0,0,0,1,1,1,1,0,0,
        0,1,1,1,1,0,0,0,0,0,0,1,1,1,1,0,
        0,1,1,1,0,0,0,0,0,0,0,0,1,1,1,0,
        1,1,1,0,0,0,0,0,0,0,0,0,0,1,1,1,
        1,1,1,0,0,0,0,0,0,0,0,0,0,1,1,1,
        1,1,1,0,0,0,0,0,0,0,0,0,0,1,1,1,
        1,1,1,0,0,0,0,0,0,0,0,0,0,1,1,1,
        1,1,1,0,0,0,0,0,0,0,0,0,0,1,1,1,
        1,1,1,0,0,0,0,0,0,0,0,0,0,1,1,1,
        0,1,1,1,0,0,0,0,0,0,0,0,1,1,1,0,
        0,1,1,1,1,0,0,0,0,0,0,1,1,1,1,0,
        0,0,1,1,1,1,0,0,0,0,1,1,1,1,0,0,
        0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,
        0,0,0,0,0,1,1,1,1,1,1,0,0,0,0,0])


def hamming_distance(vector1, vector2):
    """
    Function that computes the Hamming distance.
    """
    #Initialize the distance:
    distance = 0
    #Loop through the vectors:
    for i in range(len(vector1)):
        #Add 1 to the hamming distance where the vectors are not the same:
        if vector1[i] != vector2[i]:
            distance += 1
    return distance


def noisy_copy(array, probability):
    """
    This function returns a noisy copy of
    a given array. It adds noise based on the
    given probability. A higher probability means
    more noise.
    """
    #Initialize the noisy array:
    noisy_array = np.copy(array)
    for i in range(len(array)):
        if np.random.rand() < probability:
            #Flip between "*" and " "
            if noisy_array[i] == 1:
                noisy_array[i] = 0
            else:
                noisy_array[i] = 1
    return noisy_array

#-------------------------------------------------------



def main():

    print("\nPart 1: Plotting randomized data: -------------------------------------")
    testpat = np.random.randint(0, 2, 256)
    plot(testpat, 16)


    print("\nPart 2: Generating a ring: --------------------------------------------")
    r = ring()
    plot(r, 16)

    print("\nPart 3: Testing Enter and Lookup: -------------------------------------")
    print("\nKey:")
    key = ring()
    plot(r, 16)
    sdm = SDM(2000, 256)
    sdm.enter(key)
    print("\nRetrieved:")
    retrieved_data = sdm.lookup(key)
    plot(retrieved_data, 16)

    print("\nPart 4: Recover pattern after 25% noise added: ------------------------")
    print("\nKey:")
    key2 = noisy_copy(key, 0.25)
    plot(key2, 16)
    print("\nRetrieved:")
    retrieved_data = sdm.lookup(key2)
    plot(retrieved_data, 16)

    print("\nPart 5: Learn with the following five noisy examples --------------------")
    sdm2 = SDM(2000, 256)
    sdm2.learn(5, 0.1)
    key3 = noisy_copy(ring(), 0.1)
    print("\nTest with the following probe:")
    plot(key3, 16)
    print("\nResult:")
    plot(sdm2.test(key3), 16)
    

if __name__ == '__main__':
    main()
