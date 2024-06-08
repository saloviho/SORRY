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
- **jupyter/**: Folder containing jupyter notebooks.
  - **saloviho-DP-mobilenetv2-example.ipynb**: Example jupyter notebook that contains code for training MobileNetV2 and evaluating the results for 300x300 Malevis images
  - **saloviho-DP-mobilenetv2-malevis-multiclass.ipynb**: MobileNetV2 + 300x300 Malevis 26 class classification
  - **saloviho-DP-mobilenetv2-malevis-binary.ipynb**: MobileNetV2 + 300x300 Malevis + bening samples from SORRY dataset (binary) 
  - **saloviho-DP-mobilenetv2-SORRY-binary.ipynb**: MobileNetV2 + 300x300 SORRY + bening samples from Malevis dataset (binary) 
  - **saloviho-DP-RF-SORRY-ember-binary.ipynb**: RandomForest + EMBER features extracted from the SORRY dataset
- **saloviho-malware-visualization.pdf**: PDF presentation  

You can download the SOREL-20M metadata meta.db from the following link:

[http://sorel-20m.s3.amazonaws.com/09-DEC-2020/processed-data/meta.db](http://sorel-20m.s3.amazonaws.com/09-DEC-2020/processed-data/meta.db)

## Contributors

- Ihor Salov - Malware Detection Using Visualization Techniques - FIT CTU
