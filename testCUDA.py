import torch
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print('Using device:', device)
print()

# Additional Info when using cuda
if device.type == 'cuda':
    print('Device name: ', torch.cuda.get_device_name(0))
    print('Free: ', torch.cuda.mem_get_info()[0], ' Bytes')
    print('Total: ', torch.cuda.mem_get_info()[1], ' Bytes')
