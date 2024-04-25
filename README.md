<!-- PROJECT TITLE -->

<div>
    <h1 align="center">Strings.py</h1>
    <p>A python implementation of the UNIX strings command designed for Mach-O binaries.</p>
</div>

<!-- ABOUT THE PROJECT -->
## About The Project

This is a python implementation of the UNIX 'strings' command for for Mach-O binaries (on Mac OS X).
It will find the printable strings (currently, only ASCII) in a object or executable.

Here are some of the features
<ul>
  <li>Granulate the search area by Sections, Segments or Symbol-Tables</li>
  <li>Complete (naive) file search</li>
  <li>Print information about a given Mach-O file</li>
  <li>Supports multi-architecture binaries</li>
</ul>


mach0.py implemenrs a crude little Mach-O parser which could be further extended if you are interested.
