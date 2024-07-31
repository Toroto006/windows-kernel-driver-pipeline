import React from 'react';

import { Path } from '@/types/Pathing';
import {
  HoverCard,
  HoverCardContent,
  HoverCardTrigger,
} from "@/components/ui/hover-card"
import { nodeServerPages } from 'next/dist/build/webpack/plugins/pages-manifest-plugin';

interface LocContext {
  context: string;
  ui: () => JSX.Element;
}

interface FuncNode {
  addr: number;
  name?: string;
  context?: LocContext;
  depth: number;
  children: FuncNode[];
}

function createContext(context: string, title:string): LocContext {
  /* returns a location context object containing the React.FC */
  let lines = context.split('\n');
  let maxWidthNecessary = Math.max(...lines.map(l => l.length));
  console.log(maxWidthNecessary);
  return {
    context,
    ui: () => (
      <HoverCard>
        <HoverCardTrigger>{title}</HoverCardTrigger>
        <HoverCardContent className={`w-${maxWidthNecessary*2}`}>
        <div>
          {lines.map((line, idx) => (
            <div key={idx} style={{ whiteSpace: 'pre-wrap' }}>
              {line}
            </div>
          ))}
        </div>
        </HoverCardContent>
      </HoverCard>
    ),
  };
}

function makeFunctionTree(handlerAddr: number, paths: Path[], rootName?: string): FuncNode {
  const root: FuncNode = { addr: handlerAddr, depth: 0, children: [] };
  root.name = rootName;

  for (const p of paths) {
    // First check if the path is relevant to this tree
    if (p.path[0] !== handlerAddr) {
      continue;
    }

    // Add all intermediate nodes
    let current: FuncNode | undefined = root;
    if (p.path.length > 1) {
      for (let i = 1; i < p.path.length; i++) {
        const addr = p.path[i];
        let child : FuncNode | undefined = current.children.find(c => c.addr === addr);
        if (!child) {
          child = {
            addr,
            depth: current.depth + 1,
            children: [],
          };
          current.children.push(child);
        }
        current = child;
      }
    }

    // Add the leaf node name
    if (current) {
      current.name = p.name;
      current.context = createContext(p.context, `0x${current.addr.toString(16)} ${current.name}`);
    }
  }

  return root;
}

interface FunctionTreeProps {
  handlerAddrs: number[];
  paths: Path[];
}

const renderNode = (node: FuncNode): JSX.Element => (
    <div style={{ marginLeft: 10 }}>
        {/* add element on hover to show the context */}
        {node.name && node.context && node.context.ui()}
        {node.addr && !node.context && `0x${node.addr.toString(16)} ${node.name ? `(${node.name})` : ''}`}
        {node.children.map(child => renderNode(child))}
    </div>
);

const FunctionTree: React.FC<FunctionTreeProps> = ({ handlerAddrs, paths }) => {
    let roots = handlerAddrs.map(addr => makeFunctionTree(addr, paths));

  return (
    <div>
        {handlerAddrs && roots.map(root => renderNode(root))}
    </div>
  );
};

export default FunctionTree;
