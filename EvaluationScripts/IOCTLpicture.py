#!/usr/bin/env python3
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.legend import Legend
Line2D._us_dashSeq    = property(lambda self: self._dash_pattern[1])
Line2D._us_dashOffset = property(lambda self: self._dash_pattern[0])
Legend._ncol = property(lambda self: self._ncols)
import matplotlib.transforms as mtrans

def IOCTLpicture(save_tex=False):
    print(f"IOCTL picture creation")
    FONT_SIZE = 12
    fig, ax = plt.subplots(figsize=(12, 2))

    # Add vertical lines separating the bit segments
    for i in [2, 13, 15]:
        ax.axvline(x=i, color='black', linestyle='--')
    
    # Labels for the bit segments
    ax.text(1, 3.5, 'Transfer\nType', ha='center', va='center', fontsize=FONT_SIZE)
    ax.text(7.5, 3.5, 'Function Code', ha='center', va='center', fontsize=FONT_SIZE)
    ax.text(14, 3.5, 'Required\nAccess', ha='center', va='center', fontsize=FONT_SIZE)
    ax.text(23, 3.5, 'Device Type', ha='center', va='center', fontsize=FONT_SIZE)

    # Set the limits, labels, and title
    ax.set_xlim(0, 32)
    ax.set_ylim(2.5, 4.5)
    ax.set_yticks([])
    ax.set_xticks(range(0, 32))
    ax.set_xticklabels(range(0, 32))
    trans = mtrans.Affine2D().translate(12, 0)
    for t in ax.get_xticklabels():
        t.set_transform(t.get_transform()+trans)
    ax.set_xlabel('Bit', fontsize=14)

    plt.grid(False)
    plt.show()

    fig.tight_layout()
    #plt.show()

    if not save_tex:
        fig.savefig('figures/IOCTLpicture.svg')
    else:
        # To save it for the thesis
        fig.savefig('figures/IOCTLpicture.pdf', format="pdf", dpi=1200, bbox_inches="tight", transparent=True)

if __name__ == "__main__":
    save_tex = False

    import os
    os.system('clear')

    IOCTLpicture(save_tex=save_tex)
