import numpy as np
    
def incmatrix(genl1,genl2): !\label{anotherline}!
    m = len(genl1)
    n = len(genl2) 
    M = None #to become the incidence matrix
    VT = np.zeros((n*m,1), int)  #dummy variable
    
    #compute the bitwise xor matrix
    M1 = bitxormatrix(genl1)
    M2 = np.triu(bitxormatrix(genl2),1) 
