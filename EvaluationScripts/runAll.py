import matplotlib.pyplot as plt

import os
os.system('clear')

from pipelineEfficiency import pipelineEfficiency
from gatheringResults import gatheringResults1, gatheringResults2, gatheringResults3
from pathingResults import pathingResults
from housekeeperResults import housekeeperResults
from interestingFunctions import interestingFunctions
from IOCTLpicture import IOCTLpicture
from fuzzingResults import fuzzingResults

# latex will be slower and require a working LaTeX installation
SAVE_TEX = True

if SAVE_TEX:
    ## reset defaults
    plt.rcdefaults()
    
    plt.style.use('default')

    ## Set up LaTeX fonts
    # plt.rcParams.update({
    #     "text.usetex": True,
    #     "font.family": "serif",
    #     "font.serif": ["Computer Modern Roman"],
    #     "font.size": 12,
    #     })

print(f"Running all evaluation scripts against DB and saving to {'tex' if SAVE_TEX else 'svg'} files.")

pipelineEfficiency(save_tex=SAVE_TEX)
gatheringResults1(save_tex=SAVE_TEX)
gatheringResults2(save_tex=SAVE_TEX)
gatheringResults3(save_tex=SAVE_TEX)
pathingResults(save_tex=SAVE_TEX)
housekeeperResults(SAVE_TEX)
interestingFunctions(SAVE_TEX)
IOCTLpicture(SAVE_TEX)
fuzzingResults(SAVE_TEX)