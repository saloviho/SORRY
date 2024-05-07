# SORRY - SOREL Research imagerY dataset

## Overview

This repository contains a dataset of malware samples represented as images, along with scripts for dataset creation and manipulation. It was created as part of Malware Detection Using Visualization Technique master thesis. The dataset includes images converted from binary files representing malware samples. A subset of the SOREL-20M dataset was taken as a malware executable source.

### Dataset Structure

- **images/**: Dataset of malware converted to images. 7700 training and 3850 test images for each resolution.
  - **224x224/**: Directory containing 224x224 pixel images.
    - **test/**: Test set images.
    - **train/**: Training set images.
  - **300x300/**: Directory containing 300x300 pixel images.
    - **test/**: Test set images.
    - **train/**: Training set images.
- **scripts/**: Folder containing scripts for dataset handling.
  - **dataset.py**: Script to download and create the dataset
  - **malware2image.py**: Script to convert any binary file into image

You can download the SOREL-20M metadata meta.db from the following link:

[http://sorel-20m.s3.amazonaws.com/09-DEC-2020/processed-data/meta.db](http://sorel-20m.s3.amazonaws.com/09-DEC-2020/processed-data/meta.db)

## Contributors

- Ihor Salov - Malware Detection Using Visualization Techniques - FIT CTU
