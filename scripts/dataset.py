import sqlite3
import msgpack
import zlib
import numpy as np
import os
import tqdm
import boto3
from botocore import UNSIGNED
from botocore.client import Config
from botocore.exceptions import ClientError
from logzero import logger
import math
import shutil
from PIL import Image
import json

# This is the timestamp that divides the validation data (used to check convergence/overfitting)
# from test data (used to assess final performance)
validation_test_split =  1547279640.0
# This is the timestamp that splits training data from validation data
train_validation_split = 1543542570.0

class Dataset:
    tags = ["adware", "flooder", "ransomware", "dropper", "spyware", "packed",
            "crypto_miner", "file_infector", "installer", "worm", "downloader"]
    
    def __init__(self, metadb_path,
                 return_malicious=True, return_counts=True, return_tags=True, return_shas=True,
                 mode='train', img_size="300", img_mode="RGB", n_samples=350):
        """
        Initializes a dataset object for processing the SOREL-20M dataset.

        Args:
            metadb_path (str): Path to the SQLite database containing metadata about the dataset.
            return_malicious (bool): Whether to return information about whether each sample is malicious or not.
            return_counts (bool): Whether to return counts of certain features for each sample.
            return_tags (bool): Whether to return tags indicating the presence of specific malware families.
            return_shas (bool): Whether to return SHA256 hashes for each sample.
            mode (str): The mode of the dataset ('train', 'test', or 'validation').
            img_size (str): Size of the output images. Default is "300".
            img_mode (str): Mode of the output images ('RGB' or 'L'). Default is "RGB".
            n_samples (int): Number of samples to load per malware family. Default is 350.
        """
        if mode != 'train' and mode != 'test' and mode != 'validation':
            raise ValueError('invalid mode: {}'.format(mode))

        os.makedirs(os.path.join("bin", mode), exist_ok=True)
        os.makedirs(os.path.join("img", f"{img_size}x{img_size}", mode), exist_ok=True)
        os.makedirs(os.path.join("cat", f"{img_size}x{img_size}", mode), exist_ok=True)
        
        sha256_list, can_restore = self.restore(metadb_path, mode, img_size, img_mode)
        
        self.return_counts = return_counts
        self.return_tags = return_tags
        self.return_malicious = return_malicious
        self.return_shas = return_shas

        retrieve = ["sha256"]
        if return_malicious:
            retrieve += ["is_malware"]
        if return_counts:
            retrieve += ["rl_ls_const_positives"]
        if return_tags:
            retrieve.extend(Dataset.tags)
            
        conn = sqlite3.connect(metadb_path)
        cur = conn.cursor()
        
        query = 'select ' + ','.join(retrieve)
        query += " from meta"


        if not can_restore:
            if mode == 'train':
                query += ' where(rl_fs_t <= {})'.format(train_validation_split)
            elif mode == 'validation':
                query += ' where((rl_fs_t >= {}) and (rl_fs_t < {}))'.format(train_validation_split,
                                                                             validation_test_split)
            else:
                query += ' where(rl_fs_t >= {})'.format(config.validation_test_split)
            query += ' and (is_malware > 0)'
        else:
            sha256_list = [f'"{sha256}"' for sha256 in sha256_list]
            query += f" WHERE sha256 IN ({','.join(sha256_list)})"

        
        vals = cur.execute(query).fetchall()
        conn.close()
        
        fam_dict = {fam: 0 for fam in Dataset.tags}
        
        retrieve_ind = dict(zip(retrieve, list(range(len(retrieve)))))
        if not can_restore:
            logger.info('Creating new dataset for {} mode.'.format(mode))
            res = []
            done = 0
            for v in vals:
                if done == len(fam_dict):
                    break
                sha256 = v[retrieve_ind['sha256']]
                tags = np.asarray([v[retrieve_ind[t]] for t in Dataset.tags])
                fam_index = np.argmax(tags)
                fam = Dataset.tags[fam_index]
                
                if fam_dict[fam] < n_samples: 
                    if self.download_file_from_s3(sha256, mode):
                        self.convert_to_img(sha256, mode, img_size, img_mode)
                        res.append(v)
                        fam_dict[fam] += 1
                        
                        if fam_dict[fam] == n_samples:
                            done += 1
            vals = res
        else:
            logger.info('Restoring the dataset for {} mode.'.format(mode))
        
        logger.info(f"{len(vals)} samples loaded.")
        
        self.keylist = list(map(lambda x: x[retrieve_ind['sha256']], vals))
        if self.return_malicious:
            self.labels = list(map(lambda x: x[retrieve_ind['is_malware']], vals))
        if self.return_counts:
            self.count_labels = list(map(lambda x: x[retrieve_ind['rl_ls_const_positives']], vals))
        if self.return_tags:
            self.tag_labels = np.asarray([list(map(lambda x: x[retrieve_ind[t]], vals)) for t in Dataset.tags]).T
        
        if len(os.listdir(os.path.join("cat", f"{img_size}x{img_size}", mode))) > 0:
            logger.info('Categories folder not empty. Skipping.')
            return
        
        for i in range(0, len(self.keylist)):
            fam_index = np.argmax(self.tag_labels[i])
            fam = Dataset.tags[fam_index]
            
            fam_path = os.path.join("cat",f"{img_size}x{img_size}", mode, fam)
            if (not os.path.exists(fam_path)):
                os.mkdir(fam_path)
            
            dst_path = os.path.join(fam_path, f"{self.keylist[i]}.png")
            src_path = os.path.join("img", f"{img_size}x{img_size}", mode, self.keylist[i])
            shutil.copy(src_path, dst_path)

    def __len__(self):
        return len(self.keylist)

    def __getitem__(self, index):
        labels = {}
        key = self.keylist[index]
        if self.return_malicious:
            labels['malware'] = self.labels[index]
        if self.return_counts:
            labels['count'] = self.count_labels[index]
        if self.return_tags:
            labels['tags'] = self.tag_labels[index]
        if self.return_shas:
            return key, labels
        else:
            return labels
            
    def restore(self, metadb_path, mode, img_size, img_mode):
        img_path = os.path.join("img", f"{img_size}x{img_size}", mode)
        bin_path = os.path.join("bin", mode)
        
        file_names = [entry.name for entry in os.scandir(img_path) if entry.is_file()]
        if len(file_names) > 0:
            return file_names, True
        
        logger.info('The img directory {} is empty'.format(img_path))         
        file_names = [entry.name for entry in os.scandir(bin_path) if entry.is_file()]
        if len(file_names) > 0:
            logger.info('{} binary files found. Converting...'.format(len(file_names)))
            for sha256 in file_names:
                self.convert_to_img(sha256, mode, img_size, img_mode)
            return file_names, True
            
        logger.info('The bin directory {} is empty.'.format(bin_path))
        return [], False

    
    def convert_to_img(self, sha256, mode, img_size, img_mode):
        if img_mode == "RGB":
            channels = 3
        elif img_mode == "L":
            channels = 1
        else:
            raise ValueError('invalid image mode: {}'.format(img_mode))
    
        with open(os.path.join("bin", mode, sha256), "rb") as f:
            data = zlib.decompress(f.read())
            data = np.frombuffer(data, dtype=np.uint8)
    
        file_size = len(data)
        img_width = int(math.ceil(math.sqrt(math.ceil(float(file_size) / channels))))
        new_file_size = img_width * img_width * channels
        data = np.pad(data, (new_file_size - file_size, 0))

        result = np.zeros((img_width, img_width, channels), dtype=np.uint8)
        for row in range(0, img_width):
            for col in range(0, img_width):
                for ch in range(0, channels):
                    result[row][col][ch] = data[row * (img_width * channels) + col * channels + ch]
    
        img = Image.fromarray(result, img_mode)
        img = img.resize((int(img_size), int(img_size)), Image.LANCZOS)
        logger.info('File {} was successfully converted to {} image.'.format(sha256, img_mode))
        img.save(os.path.join("img", f"{img_size}x{img_size}", mode, sha256), format="PNG") 
    
    def download_file_from_s3(self, sha256, mode):
        s3 = boto3.client('s3', config=Config(signature_version=UNSIGNED))
        try:
            path = os.path.join("bin", mode, sha256)
            s3.download_file("sorel-20m", f"09-DEC-2020/binaries/{sha256}", path)
            
            logger.info('File {} was successfully downloaded.'.format(sha256))
            return True
        except ClientError:
            return False
          
            
if __name__ == '__main__':
    metadb_path = os.path.join("../", 'meta.db')
    ds = Dataset(metadb_path=metadb_path, mode="train", img_size=300, img_mode="RGB", n_samples=10)
