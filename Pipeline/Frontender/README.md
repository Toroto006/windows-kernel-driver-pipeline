# Frontender Module: Security Researcher Interaction
Frontender is a module designed to assist security researchers by presenting driver analysis results in a navigable format. It is part of a pipeline that collects and analyzes drivers to identify potential vulnerabilities through static and dynamic methods. The Frontender provides a website that allows researchers to verify these results, modify driver metadata, and add jobs to the fuzzing queue.

Frontender streamlines the process of verifying driver vulnerabilities, providing a comprehensive tool for security researchers to manage and analyze driver data effectively.

## Technical Overview
Frontender runs as a containerized Node.js server (version 18) hosting a React website developed in TypeScript. It uses shadcn/ui components for styling and Vercel's stale-while-revalidate (SWR) for HTTP caching to enhance the user experience.

## Website Features
The website features three main tabs for displaying pipeline data:

- `Drivers Tab`: Displays all drivers in the database with filtering and search options.
- `Drivers by Origin Tab`: Restricts displayed drivers to those from a specific origin.
- `Drivers by Imports Tab`: Shows drivers based on imported functions specified in the search field.
- `Fuzzing Queue Tab:` Displays tables of drivers currently being fuzzed, those that finished or encountered errors, and those still in the queue.
- `Known Vulnerable Drivers Tab`: Lists known vulnerable drivers in a table format similar to the driver's overview.

Each driver can be inspected in detail by clicking its filename, revealing metadata, identification results, certificate details, and fuzzing statistics. Users can modify driver tags, add drivers to the fuzzing queue, and download drivers.

## Learn More about Next.js
This is a [Next.js](https://nextjs.org/) project bootstrapped with [`create-next-app`](https://github.com/vercel/next.js/tree/canary/packages/create-next-app).

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js/) - your feedback and contributions are welcome!

## License
This project is under [GPLv3](../../LICENSE), but any of the shadcn/ui elements are licensed under [LICENSE_shadcnui](./LICENSE_shadcnui) and similarly any next.js elements under [LICENSE_nextjs](./LICENSE_nextjs).