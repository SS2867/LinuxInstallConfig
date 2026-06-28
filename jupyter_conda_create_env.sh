#!/bin/bash

echo "Enter the environment to activate (use /xx/xx to use in paths)"
read envname
read -p "Is this a --prefix path (enter Y)" prefix
if [ $prefix=="Y" ]; then prefix="--prefix"; fi
echo "Enter extra params (like --python=3.13)"
read params

/home/zelin/miniconda3/bin/conda create $prefix $envname $params

/home/zelin/miniconda3/bin/conda activate $envname

python -m pip install ipykernel jupyterlab

echo $envname
/home/zelin/miniconda3/bin/conda env list

read -p "Do you want to register with ipykernel, if yes, enter dispname:" dispname
if [ ! -z $dispname ] ; then
 python -m ipykernel install --user --name $dispname --display-name "Python ($dispname)"
fi

exit 0



