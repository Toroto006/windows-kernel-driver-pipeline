export interface Path {
    id: number;
    isfor: number;
    name: string;
    context: string;
    path: number[]; // Assuming the path is stored as a string for simplicity
}

export interface IoctlComparison {
    op: string;
    val: number;
    line: string;
}
  
export interface PathingResult {
    combined_sub_functions: number;
    created_at: string;
    handler_addrs: number[]; // Assuming the handler addresses are stored as a string for simplicity
    ioctl_comp: IoctlComparison[]; // Assuming the handler addresses are stored as a string for simplicity
    id: number;
    paths: Path[];
    ret_code: number;
    type: string;
}