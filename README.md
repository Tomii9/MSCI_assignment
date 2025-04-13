# ip-tool
This tool's purpose is to check for IP network collisions in the k8s cluster.

## Usage

1. Apply the DaemonSet
```
kubectl apply -f ip-tool-daemonset.yaml
```
2. Aggregate the output
```
kubectl logs -l app=ip-tool > $OUTPUT_FILE_NAME
```
3. Check for collisions
```
./ip_tool.py --check-collision $OUTPUT_FILE_NAME
```
4. Delete the DaemonSet
```
kubectl delete -f ip-tool-daemonset.yaml
```